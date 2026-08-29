// SPDX-License-Identifier: Apache-2.0 or MIT

//! Integration tests for controlled cgroup environments created by the QEMU suite.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use cgroups_rs::fs::hierarchies;
use cgroups_rs::fs::pid::PidController;
use cgroups_rs::fs::{Cgroup, Hierarchy, Subsystem};
use cgroups_rs::CgroupPid;

#[derive(Clone, Debug)]
struct DelegatedV2Hierarchy {
    root: PathBuf,
}

impl DelegatedV2Hierarchy {
    fn new(root: PathBuf) -> Self {
        Self { root }
    }
}

impl Hierarchy for DelegatedV2Hierarchy {
    fn subsystems(&self) -> Vec<Subsystem> {
        vec![Subsystem::Pid(PidController::new(
            self.root.clone(),
            PathBuf::new(),
            true,
        ))]
    }

    fn root(&self) -> PathBuf {
        self.root.clone()
    }

    fn root_control_group(&self) -> Cgroup {
        Cgroup::load(Box::new(self.clone()), "")
    }

    fn parent_control_group(&self, path: &str) -> Cgroup {
        let parent = Path::new(path).parent().unwrap_or_else(|| Path::new(""));
        Cgroup::load(Box::new(self.clone()), parent)
    }

    fn v2(&self) -> bool {
        true
    }
}

fn current_v2_path() -> String {
    let membership = fs::read_to_string("/proc/self/cgroup").expect("read live /proc/self/cgroup");
    membership
        .lines()
        .find_map(|line| line.strip_prefix("0::"))
        .expect("find the unified hierarchy membership")
        .to_string()
}

/// Move the test harness out of the delegated root before using that root as
/// an inner node. The transient systemd unit removes this manager leaf after
/// the test process exits.
fn move_self_to_manager_leaf(root: &Path) {
    let pid = std::process::id().to_string();
    let manager_leaf = root.join(format!("cgroups-rs-manager-{}", pid));
    fs::create_dir(&manager_leaf).expect("create a manager leaf cgroup");
    fs::write(manager_leaf.join("cgroup.procs"), pid.as_bytes())
        .expect("move the test harness into the manager leaf cgroup");

    let root_procs =
        fs::read_to_string(root.join("cgroup.procs")).expect("read delegated root cgroup.procs");
    assert!(
        !root_procs.lines().any(|line| line == pid.as_str()),
        "the delegated root must not directly contain the test process"
    );
}

fn exercise_v2_hierarchy(hierarchy: Box<dyn Hierarchy>, root: &Path) {
    let name = format!("cgroups-rs-environment-{}", std::process::id());
    let cgroup = Cgroup::new(hierarchy, &name).expect("create a child cgroup");
    assert!(cgroup.exists(), "new child cgroup must exist");
    let cgroup_type =
        fs::read_to_string(root.join(&name).join("cgroup.type")).expect("read child cgroup.type");
    assert_eq!(
        cgroup_type.trim(),
        "domain",
        "new child cgroup must be a valid domain"
    );

    let mut child = Command::new("sleep")
        .arg("infinity")
        .spawn()
        .expect("spawn a process to attach");
    if let Err(error) = cgroup.add_task_by_tgid(CgroupPid::from(child.id() as u64)) {
        let _ = child.kill();
        let _ = child.wait();
        let _ = cgroup.delete();
        panic!("attach child process to delegated cgroup: {:?}", error);
    }

    let procs =
        fs::read_to_string(root.join(&name).join("cgroup.procs")).expect("read child cgroup.procs");
    let child_pid = child.id().to_string();
    assert!(
        procs.lines().any(|line| line == child_pid.as_str()),
        "child PID must be visible in the child cgroup"
    );

    child.kill().expect("kill attached child process");
    child.wait().expect("reap attached child process");
    cgroup.delete().expect("delete empty child cgroup");
}

fn live_cgroup2_mount() -> (PathBuf, PathBuf) {
    let mountinfo =
        fs::read_to_string("/proc/self/mountinfo").expect("read live /proc/self/mountinfo");
    mountinfo
        .lines()
        .find_map(|line| {
            let (mount_fields, fs_fields) = line.split_once(" - ")?;
            if fs_fields.split_whitespace().next()? != "cgroup2" {
                return None;
            }
            let fields: Vec<_> = mount_fields.split_whitespace().collect();
            if fields.len() < 6 {
                return None;
            }
            Some((PathBuf::from(fields[3]), PathBuf::from(fields[4])))
        })
        .expect("find the live cgroup2 mount")
}

#[test]
#[ignore]
fn delegated_rootless_v2() {
    assert_ne!(
        unsafe { libc::geteuid() },
        0,
        "delegation test must run as a non-root user"
    );

    let membership = current_v2_path();
    assert_ne!(
        membership, "/",
        "delegation test must run inside a non-root cgroup"
    );
    let delegated_root = Path::new("/sys/fs/cgroup").join(membership.trim_start_matches('/'));
    assert!(
        delegated_root.join("cgroup.procs").exists(),
        "delegated cgroup must be visible at {}",
        delegated_root.display()
    );

    move_self_to_manager_leaf(&delegated_root);
    exercise_v2_hierarchy(
        Box::new(DelegatedV2Hierarchy::new(delegated_root.clone())),
        &delegated_root,
    );
}

#[test]
#[ignore]
fn cgroup_namespace_nested_v2() {
    assert_eq!(
        current_v2_path(),
        "/",
        "the service cgroup must become the cgroup namespace root"
    );
    assert!(
        hierarchies::is_cgroup2_unified_mode(),
        "the private /sys/fs/cgroup mount must be cgroup2"
    );

    let (mount_root, mount_point) = live_cgroup2_mount();
    assert_eq!(mount_root, PathBuf::from("/"));
    assert_eq!(mount_point, PathBuf::from("/sys/fs/cgroup"));

    move_self_to_manager_leaf(Path::new("/sys/fs/cgroup"));
    exercise_v2_hierarchy(hierarchies::auto(), Path::new("/sys/fs/cgroup"));
}
