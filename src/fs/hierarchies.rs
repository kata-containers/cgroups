// Copyright (c) 2018 Levente Kurusa
// Copyright (c) 2020 Ant Group
//
// SPDX-License-Identifier: Apache-2.0 or MIT
//

//! This module represents the various control group hierarchies the Linux kernel supports.

use std::fs;
use std::path::{Path, PathBuf};

use crate::discovery::mountinfo::{parse_mountinfo_line, MountRecord};
use crate::fs::blkio::BlkIoController;
use crate::fs::cpu::CpuController;
use crate::fs::cpuacct::CpuAcctController;
use crate::fs::cpuset::CpuSetController;
use crate::fs::devices::DevicesController;
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

use crate::fs::cgroup::Cgroup;

/// Process mounts information.
///
/// See `proc(5)` for format details.
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct Mountinfo {
    /// Mount root directory of the file system.
    pub mount_root: PathBuf,
    /// Mount pathname relative to the process's root.
    pub mount_point: PathBuf,
    /// Filesystem type (main type with optional sub-type).
    pub fs_type: (String, Option<String>),
    /// Superblock options.
    pub super_opts: Vec<String>,
}

impl From<MountRecord> for Mountinfo {
    fn from(record: MountRecord) -> Self {
        Mountinfo {
            mount_root: record.mount_root,
            mount_point: record.mount_point,
            fs_type: record.fs_type,
            super_opts: record.super_opts,
        }
    }
}

/// Parse a single mountinfo line, forwarding to the discovery parser.
///
/// Transitional shim over [`parse_mountinfo_line`]: the legacy
/// `Option`-based contract cannot carry parse errors, so a malformed
/// line degrades to `None` exactly as the previous hand-written parser
/// skipped it. Escape decoding and strict field validation come from
/// the discovery implementation.
pub(crate) fn parse_mountinfo_for_line(line: &str) -> Option<Mountinfo> {
    parse_mountinfo_line(line, 1).ok().map(Mountinfo::from)
}

fn parse_v1_mountinfo_line(line: &str) -> Option<Mountinfo> {
    parse_mountinfo_for_line(line).filter(|mount| mount.fs_type.0 == "cgroup")
}

/// Parse v1 cgroup mount lines from `/proc/self/mountinfo` content.
fn mountinfo_file_str(input: &str) -> Vec<Mountinfo> {
    input.lines().filter_map(parse_v1_mountinfo_line).collect()
}

/// Returns mounts information for the current process.
pub fn mountinfo_self() -> Vec<Mountinfo> {
    match fs::read_to_string("/proc/self/mountinfo") {
        Ok(data) => mountinfo_file_str(&data),
        Err(_) => vec![],
    }
}

/// The standard, original cgroup implementation. Often referred to as "cgroupv1".
#[derive(Debug, Clone)]
pub struct V1 {
    mountinfo: Vec<Mountinfo>,
}

#[derive(Debug, Clone)]
pub struct V2 {
    root: String,
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
            subs.push(Subsystem::HugeTlb(HugeTlbController::new(
                point, root, false,
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

    fn root_control_group(&self) -> Cgroup {
        Cgroup::load(auto(), "")
    }

    fn parent_control_group(&self, path: &str) -> Cgroup {
        let path = Path::new(path);
        let parent_path = path.parent().unwrap().to_string_lossy().to_string();
        Cgroup::load(auto(), parent_path)
    }

    fn root(&self) -> PathBuf {
        self.mountinfo
            .iter()
            .find_map(|m| {
                if m.fs_type.0 == "cgroup" {
                    return Some(m.mount_point.parent().unwrap());
                }
                None
            })
            .unwrap()
            .to_path_buf()
    }
}

impl Hierarchy for V2 {
    fn v2(&self) -> bool {
        true
    }

    fn subsystems(&self) -> Vec<Subsystem> {
        let p = format!("{}/{}", UNIFIED_MOUNTPOINT, "cgroup.controllers");
        let ret = fs::read_to_string(p.as_str());
        if ret.is_err() {
            return vec![];
        }

        let mut subs = vec![];

        let controllers = ret.unwrap().trim().to_string();
        let mut controller_list: Vec<&str> = controllers.split(' ').collect();

        // The freezer functionality is present in V2, but not as a controller,
        // but apparently as a core functionality. FreezerController supports
        // that, but we must explicitly fake the controller here.
        controller_list.push("freezer");

        for s in controller_list {
            match s {
                "cpu" => {
                    subs.push(Subsystem::Cpu(CpuController::new(
                        self.root(),
                        PathBuf::from(""),
                        true,
                    )));
                }
                "io" => {
                    subs.push(Subsystem::BlkIo(BlkIoController::new(
                        self.root(),
                        PathBuf::from(""),
                        true,
                    )));
                }
                "cpuset" => {
                    subs.push(Subsystem::CpuSet(CpuSetController::new(
                        self.root(),
                        PathBuf::from(""),
                        true,
                    )));
                }
                "memory" => {
                    subs.push(Subsystem::Mem(MemController::new(
                        self.root(),
                        PathBuf::from(""),
                        true,
                    )));
                }
                "pids" => {
                    subs.push(Subsystem::Pid(PidController::new(
                        self.root(),
                        PathBuf::from(""),
                        true,
                    )));
                }
                "freezer" => {
                    subs.push(Subsystem::Freezer(FreezerController::new(
                        self.root(),
                        PathBuf::from(""),
                        true,
                    )));
                }
                "hugetlb" => {
                    subs.push(Subsystem::HugeTlb(HugeTlbController::new(
                        self.root(),
                        PathBuf::from(""),
                        true,
                    )));
                }
                _ => {}
            }
        }

        subs
    }

    fn root_control_group(&self) -> Cgroup {
        Cgroup::load(auto(), "")
    }

    fn parent_control_group(&self, path: &str) -> Cgroup {
        let path = Path::new(path);
        let parent_path = path.parent().unwrap().to_string_lossy().to_string();
        Cgroup::load(auto(), parent_path)
    }

    fn root(&self) -> PathBuf {
        PathBuf::from(self.root.clone())
    }
}

impl V1 {
    /// Finds where control groups are mounted to and returns a hierarchy in which control groups
    /// can be created.
    pub fn new() -> V1 {
        V1 {
            mountinfo: mountinfo_self(),
        }
    }

    pub fn get_mount_point(&self, controller: Controllers) -> Option<(PathBuf, PathBuf)> {
        self.mountinfo.iter().find_map(|m| {
            if m.fs_type.0 == "cgroup" && m.super_opts.contains(&controller.to_string()) {
                return Some((m.mount_point.to_owned(), m.mount_root.to_owned()));
            }
            None
        })
    }
}

impl Default for V1 {
    fn default() -> Self {
        Self::new()
    }
}

impl V2 {
    /// Finds where control groups are mounted to and returns a hierarchy in which control groups
    /// can be created.
    pub fn new() -> V2 {
        V2 {
            root: String::from(UNIFIED_MOUNTPOINT),
        }
    }
}

impl Default for V2 {
    fn default() -> Self {
        Self::new()
    }
}

pub const UNIFIED_MOUNTPOINT: &str = "/sys/fs/cgroup";

pub fn is_cgroup2_unified_mode() -> bool {
    use nix::sys::statfs;

    let path = std::path::Path::new(UNIFIED_MOUNTPOINT);
    let fs_stat = match statfs::statfs(path) {
        Ok(fs_stat) => fs_stat,
        Err(_) => return false,
    };

    fs_stat.filesystem_type() == statfs::CGROUP2_SUPER_MAGIC
}

pub fn auto() -> Box<dyn Hierarchy> {
    if is_cgroup2_unified_mode() {
        Box::new(V2::new())
    } else {
        Box::new(V1::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One mountinfo line plus its expected parse result.
    ///
    /// `expect` is `None` when the parser must reject the line, otherwise it
    /// pins every `Mountinfo` field: `(mount_root, mount_point,
    /// fs_type_main, fs_type_sub, super_opts)`. Keeping input and expectation
    /// adjacent makes failures precise and lets known defects surface as a
    /// visible expected value rather than prose in a separate fixture header.
    /// Pinned expectation for a parsed mountinfo line: mount_root,
    /// mount_point, fs_type main, fs_type sub, super_opts.
    type Expect = (
        &'static str,
        &'static str,
        &'static str,
        Option<&'static str>,
        &'static [&'static str],
    );

    struct Case {
        name: &'static str,
        line: &'static str,
        expect: Option<Expect>,
    }

    const CASES: &[Case] = &[
        // --- v1 mixed: every line is a cgroup v1 mount with mount_root "/".
        Case {
            name: "v1-mixed: systemd",
            line: "35 33 0:30 / /sys/fs/cgroup/systemd rw,nosuid,nodev,noexec,relatime shared:11 - cgroup cgroup rw,xattr,name=systemd",
            expect: Some(("/", "/sys/fs/cgroup/systemd", "cgroup", None, &["rw", "xattr", "name=systemd"])),
        },
        Case {
            name: "v1-mixed: hugetlb",
            line: "38 33 0:33 / /sys/fs/cgroup/hugetlb rw,nosuid,nodev,noexec,relatime shared:15 - cgroup cgroup rw,hugetlb",
            expect: Some(("/", "/sys/fs/cgroup/hugetlb", "cgroup", None, &["rw", "hugetlb"])),
        },
        Case {
            name: "v1-mixed: net_cls,net_prio",
            line: "39 33 0:34 / /sys/fs/cgroup/net_cls,net_prio rw,nosuid,nodev,noexec,relatime shared:16 - cgroup cgroup rw,net_cls,net_prio",
            expect: Some(("/", "/sys/fs/cgroup/net_cls,net_prio", "cgroup", None, &["rw", "net_cls", "net_prio"])),
        },
        Case {
            name: "v1-mixed: cpuset",
            line: "40 33 0:35 / /sys/fs/cgroup/cpuset rw,nosuid,nodev,noexec,relatime shared:17 - cgroup cgroup rw,cpuset",
            expect: Some(("/", "/sys/fs/cgroup/cpuset", "cgroup", None, &["rw", "cpuset"])),
        },
        Case {
            name: "v1-mixed: blkio",
            line: "41 33 0:36 / /sys/fs/cgroup/blkio rw,nosuid,nodev,noexec,relatime shared:18 - cgroup cgroup rw,blkio",
            expect: Some(("/", "/sys/fs/cgroup/blkio", "cgroup", None, &["rw", "blkio"])),
        },
        Case {
            name: "v1-mixed: devices",
            line: "42 33 0:37 / /sys/fs/cgroup/devices rw,nosuid,nodev,noexec,relatime shared:19 - cgroup cgroup rw,devices",
            expect: Some(("/", "/sys/fs/cgroup/devices", "cgroup", None, &["rw", "devices"])),
        },
        Case {
            name: "v1-mixed: memory",
            line: "43 33 0:38 / /sys/fs/cgroup/memory rw,nosuid,nodev,noexec,relatime shared:20 - cgroup cgroup rw,memory",
            expect: Some(("/", "/sys/fs/cgroup/memory", "cgroup", None, &["rw", "memory"])),
        },
        Case {
            name: "v1-mixed: freezer",
            line: "44 33 0:39 / /sys/fs/cgroup/freezer rw,nosuid,nodev,noexec,relatime shared:21 - cgroup cgroup rw,freezer",
            expect: Some(("/", "/sys/fs/cgroup/freezer", "cgroup", None, &["rw", "freezer"])),
        },
        Case {
            name: "v1-mixed: rdma",
            line: "45 33 0:40 / /sys/fs/cgroup/rdma rw,nosuid,nodev,noexec,relatime shared:22 - cgroup cgroup rw,rdma",
            expect: Some(("/", "/sys/fs/cgroup/rdma", "cgroup", None, &["rw", "rdma"])),
        },
        Case {
            name: "v1-mixed: misc",
            line: "46 33 0:41 / /sys/fs/cgroup/misc rw,nosuid,nodev,noexec,relatime shared:23 - cgroup cgroup rw,misc",
            expect: Some(("/", "/sys/fs/cgroup/misc", "cgroup", None, &["rw", "misc"])),
        },
        Case {
            name: "v1-mixed: perf_event",
            line: "47 33 0:42 / /sys/fs/cgroup/perf_event rw,nosuid,nodev,noexec,relatime shared:24 - cgroup cgroup rw,perf_event",
            expect: Some(("/", "/sys/fs/cgroup/perf_event", "cgroup", None, &["rw", "perf_event"])),
        },
        Case {
            name: "v1-mixed: cpu,cpuacct",
            line: "48 33 0:43 / /sys/fs/cgroup/cpu,cpuacct rw,nosuid,nodev,noexec,relatime shared:25 - cgroup cgroup rw,cpu,cpuacct",
            expect: Some(("/", "/sys/fs/cgroup/cpu,cpuacct", "cgroup", None, &["rw", "cpu", "cpuacct"])),
        },
        Case {
            name: "v1-mixed: pids",
            line: "49 33 0:44 / /sys/fs/cgroup/pids rw,nosuid,nodev,noexec,relatime shared:26 - cgroup cgroup rw,pids",
            expect: Some(("/", "/sys/fs/cgroup/pids", "cgroup", None, &["rw", "pids"])),
        },
        // --- v2 unified: single cgroup2 line; parsed by the line parser even
        //     though mountinfo_file_str drops it (filter tested separately).
        Case {
            name: "v2-unified: cgroup2 at /sys/fs/cgroup",
            line: "47 44 0:30 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime shared:7 - cgroup2 cgroup2 rw",
            expect: Some(("/", "/sys/fs/cgroup", "cgroup2", None, &["rw"])),
        },
        // --- namespaced: mount_root is the container subtree, not "/".
        Case {
            name: "namespaced: cpu,cpuacct root is /docker/abcd1234",
            line: "50 22 0:26 /docker/abcd1234 /sys/fs/cgroup/cpu,cpuacct rw,relatime shared:10 - cgroup cgroup rw,cpu,cpuacct",
            expect: Some(("/docker/abcd1234", "/sys/fs/cgroup/cpu,cpuacct", "cgroup", None, &["rw", "cpu", "cpuacct"])),
        },
        Case {
            name: "namespaced: memory root is /docker/abcd1234",
            line: "51 22 0:27 /docker/abcd1234 /sys/fs/cgroup/memory rw,relatime shared:11 - cgroup cgroup rw,memory",
            expect: Some(("/docker/abcd1234", "/sys/fs/cgroup/memory", "cgroup", None, &["rw", "memory"])),
        },
        Case {
            name: "namespaced: cgroup2 root is /docker/abcd1234",
            line: "52 22 0:28 /docker/abcd1234 /sys/fs/cgroup rw,relatime shared:12 - cgroup2 cgroup2 rw,nsdelegate",
            expect: Some(("/docker/abcd1234", "/sys/fs/cgroup", "cgroup2", None, &["rw", "nsdelegate"])),
        },
        // --- colon path: colon inside mount_point must be preserved.
        Case {
            name: "colon-path: mount_point /sys/fs/cgroup/work:dev",
            line: "70 26 0:26 / /sys/fs/cgroup/work:dev rw,nosuid,nodev,noexec,relatime shared:22 - cgroup cgroup rw,memory",
            expect: Some(("/", "/sys/fs/cgroup/work:dev", "cgroup", None, &["rw", "memory"])),
        },
        // --- fs_type with a subtype.
        Case {
            name: "fs_type subtype: tmpfs.123",
            line: "121 1731 0:42 / /shm rw,nosuid,nodev,noexec,relatime shared:68 master:66 - tmpfs.123 shm rw,size=65536k",
            expect: Some(("/", "/shm", "tmpfs", Some("123"), &["rw", "size=65536k"])),
        },
        // TODO: deferred parser defect. In /proc/self/mountinfo (see proc(5)),
        // characters such as space, tab, newline, and backslash in mount paths
        // are octal-escaped (e.g. \040 for space, \011 for tab).
        // `parse_mountinfo_for_line` currently does NOT unescape \040/\011.
        // Expected values record the current literal behavior so this characterization
        // test pins existing behavior; a follow-up fix should implement octal
        // unescaping and flip the expectations to the decoded form:
        //   - "/sys/fs/cgroup/my\\040dir" -> "/sys/fs/cgroup/my dir"
        //   - "/sys/fs/cgroup/tab\\011dir" -> "/sys/fs/cgroup/tab\tdir"

        // --- fs_type with several dots: split on the first dot only, the
        //     rest is the subtype (the old parser rejected these lines).
        Case {
            name: "fs_type: multiple dots split on the first only",
            line: "82 26 0:26 / /sys/fs/cgroup rw,nosuid shared:23 - cgroup.v1.extra cgroup rw,memory",
            expect: Some(("/", "/sys/fs/cgroup", "cgroup", Some("v1.extra"), &["rw", "memory"])),
        },
        Case {
            name: "fs_type: cgroup2 subtype containing dots",
            line: "86 26 0:27 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime shared:26 - cgroup2.v2.extra cgroup2 rw",
            expect: Some(("/", "/sys/fs/cgroup", "cgroup2", Some("v2.extra"), &["rw"])),
        },
        // --- escaped: \040/\011 are decoded per proc(5) now that the
        //     line parser forwards to `discovery::mountinfo`.
        Case {
            name: "escaped: \\040 decodes to a space",
            line: "60 26 0:26 / /sys/fs/cgroup/my\\040dir rw,nosuid,nodev,noexec,relatime shared:20 - cgroup cgroup rw,memory",
            expect: Some(("/", "/sys/fs/cgroup/my dir", "cgroup", None, &["rw", "memory"])),
        },
        Case {
            name: "escaped: \\011 decodes to a tab",
            line: "61 26 0:27 / /sys/fs/cgroup/tab\\011dir rw,nosuid,nodev,noexec,relatime shared:21 - cgroup cgroup rw,memory",
            expect: Some(("/", "/sys/fs/cgroup/tab\tdir", "cgroup", None, &["rw", "memory"])),
        },
        // --- malformed: every line below is rejected by the line parser.
        Case {
            name: "malformed: no separator",
            line: "no separator here",
            expect: None,
        },
        Case {
            name: "malformed: fewer than 3 fields after separator",
            line: "83 26 0:26 / /sys/fs/cgroup rw,nosuid shared:23 - cgroup cgroup",
            expect: None,
        },
        Case {
            name: "malformed: cgroup2 line with no separator",
            line: "84 26 0:27 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime shared:24 cgroup2 cgroup2 rw",
            expect: None,
        },
        Case {
            name: "malformed: cgroup2 with fewer than 3 fields after separator",
            line: "85 26 0:27 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime shared:25 - cgroup2 cgroup2",
            expect: None,
        },
    ];

    #[test]
    fn test_parse_mountinfo_for_line_table() {
        for case in CASES {
            let got = parse_mountinfo_for_line(case.line);
            match case.expect {
                None => assert!(
                    got.is_none(),
                    "{}: expected reject, got {:?}",
                    case.name,
                    got
                ),
                Some((root, point, fst_main, fst_sub, opts)) => {
                    let mi = match got {
                        Some(mi) => mi,
                        None => panic!("{}: expected Some, got None", case.name),
                    };
                    assert_eq!(
                        mi.mount_root,
                        PathBuf::from(root),
                        "{}: mount_root",
                        case.name
                    );
                    assert_eq!(
                        mi.mount_point,
                        PathBuf::from(point),
                        "{}: mount_point",
                        case.name
                    );
                    assert_eq!(mi.fs_type.0, fst_main, "{}: fs_type.0", case.name);
                    assert_eq!(mi.fs_type.1.as_deref(), fst_sub, "{}: fs_type.1", case.name);
                    assert_eq!(
                        mi.super_opts,
                        opts.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                        "{}: super_opts",
                        case.name
                    );
                }
            }
        }
    }

    /// Keeps only lines whose filesystem type is cgroup v1, dropping cgroup2
    /// and unrelated filesystems.
    #[test]
    fn test_mountinfo_file_str_filter() {
        let hybrid = "\
33 24 0:28 / /sys/fs/cgroup ro,nosuid,nodev,noexec shared:9 - tmpfs tmpfs ro,size=4096k,nr_inodes=1024,mode=755,inode64
34 33 0:29 / /sys/fs/cgroup/unified rw,nosuid,nodev,noexec,relatime shared:10 - cgroup2 cgroup2 rw,nsdelegate
35 33 0:30 / /sys/fs/cgroup/systemd rw,nosuid,nodev,noexec,relatime shared:11 - cgroup cgroup rw,xattr,name=systemd
43 33 0:38 / /sys/fs/cgroup/memory rw,nosuid,nodev,noexec,relatime shared:20 - cgroup cgroup rw,memory
48 33 0:43 / /sys/fs/cgroup/cpu,cpuacct rw,nosuid,nodev,noexec,relatime shared:25 - cgroup cgroup rw,cpu,cpuacct
49 33 0:44 / /sys/fs/cgroup/pids rw,nosuid,nodev,noexec,relatime shared:26 - cgroup cgroup rw,pids";

        let kept = mountinfo_file_str(hybrid);
        assert_eq!(kept.len(), 4, "tmpfs and cgroup2 must be dropped");
        for mi in &kept {
            assert_eq!(
                mi.fs_type.0, "cgroup",
                "only cgroup v1 kept, got {:?}",
                mi.fs_type.0
            );
        }
        let points: Vec<&str> = kept
            .iter()
            .map(|m| m.mount_point.to_str().unwrap())
            .collect();
        assert!(points.contains(&"/sys/fs/cgroup/systemd"));
        assert!(points.contains(&"/sys/fs/cgroup/memory"));
        assert!(points.contains(&"/sys/fs/cgroup/cpu,cpuacct"));
        assert!(points.contains(&"/sys/fs/cgroup/pids"));
        assert!(
            !points.contains(&"/sys/fs/cgroup/unified"),
            "cgroup2 dropped"
        );
        assert!(!points.iter().any(|p| p.contains("tmpfs")), "tmpfs dropped");
    }

    #[test]
    fn test_parse_mount() {
        let mountinfo = vec![
            ("29 26 0:26 / /sys/fs/cgroup/cpuset,cpu,cpuacct rw,nosuid,nodev,noexec,relatime shared:10 - cgroup cgroup rw,cpuset,cpu,cpuacct",
             Mountinfo{mount_root: PathBuf::from("/"), mount_point: PathBuf::from("/sys/fs/cgroup/cpuset,cpu,cpuacct"), fs_type: ("cgroup".to_string(), None), super_opts: vec![
                "rw".to_string(),
                "cpuset".to_string(),
                "cpu".to_string(),
                "cpuacct".to_string(),
             ]}),
            ("121 1731 0:42 / /shm rw,nosuid,nodev,noexec,relatime shared:68 master:66 - tmpfs shm rw,size=65536k",
             Mountinfo{mount_root: PathBuf::from("/"), mount_point: PathBuf::from("/shm"), fs_type: ("tmpfs".to_string(), None), super_opts: vec![
                "rw".to_string(),
                "size=65536k".to_string(),
             ]}),
            ("121 1731 0:42 / /shm rw,nosuid,nodev,noexec,relatime shared:68 master:66 - tmpfs.123 shm rw,size=65536k",
             Mountinfo{mount_root: PathBuf::from("/"), mount_point: PathBuf::from("/shm"), fs_type: ("tmpfs".to_string(), Some("123".to_string())), super_opts: vec![
                "rw".to_string(),
                "size=65536k".to_string(),
             ]}),
        ];

        for mi in mountinfo {
            let info = parse_mountinfo_for_line(mi.0).unwrap();
            assert_eq!(info, mi.1)
        }
    }
}
