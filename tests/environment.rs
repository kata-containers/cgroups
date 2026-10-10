// Copyright (c) 2026 Kata Contributors
//
// SPDX-License-Identifier: Apache-2.0 or MIT
//

//! Integration tests for controlled cgroup environments created by the QEMU suite.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use cgroups_rs::core::CgroupPath;
use cgroups_rs::fs::hierarchies;
use cgroups_rs::fs::pid::PidController;
use cgroups_rs::fs::{Cgroup, ControllerSelection, Hierarchy, MaxValue, Subsystem};
use cgroups_rs::CgroupPid;
use std::sync::Arc;

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

    fn root(&self) -> cgroups_rs::fs::error::Result<PathBuf> {
        Ok(self.root.clone())
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

/// Prepare a delegated parent to distribute the pids controller to children.
///
/// Move every process out of the parent to satisfy cgroup v2's no-internal-
/// process constraint. This includes both the test harness and, in the cgroup
/// namespace scenario, the waiting parent created by `unshare --fork`. The
/// transient systemd unit removes the manager leaf after those processes exit.
fn prepare_parent_for_pids(root: &Path) -> Vec<String> {
    let controllers =
        fs::read_to_string(root.join("cgroup.controllers")).expect("read parent controllers");
    assert!(
        controllers.split_whitespace().any(|name| name == "pids"),
        "pids controller must be available in {}: {:?}",
        root.display(),
        controllers
    );

    let pid = std::process::id().to_string();
    let manager_leaf = root.join(format!("cgroups-rs-manager-{}", pid));
    fs::create_dir(&manager_leaf).expect("create a manager leaf cgroup");

    let root_procs =
        fs::read_to_string(root.join("cgroup.procs")).expect("read delegated root cgroup.procs");
    let root_pids: Vec<_> = root_procs.lines().map(str::to_string).collect();
    assert!(
        root_pids.iter().any(|root_pid| root_pid == &pid),
        "the delegated root must initially contain the test process"
    );

    for root_pid in &root_pids {
        fs::write(manager_leaf.join("cgroup.procs"), root_pid.as_bytes())
            .unwrap_or_else(|error| panic!("move PID {} into manager leaf: {}", root_pid, error));
    }

    let remaining =
        fs::read_to_string(root.join("cgroup.procs")).expect("re-read delegated root cgroup.procs");
    assert!(
        remaining.trim().is_empty(),
        "parent cgroup must have no internal processes before enabling controllers: {:?}",
        remaining
    );

    fs::write(root.join("cgroup.subtree_control"), b"+pids")
        .expect("enable pids controller for child cgroups");
    let subtree_control = fs::read_to_string(root.join("cgroup.subtree_control"))
        .expect("read parent cgroup.subtree_control");
    assert!(
        subtree_control
            .split_whitespace()
            .any(|name| name == "pids"),
        "pids controller must be enabled for children of {}: {:?}",
        root.display(),
        subtree_control
    );

    root_pids
}

fn exercise_v2_hierarchy(hierarchy: Arc<dyn Hierarchy>, root: &Path) {
    let name = format!("cgroups-rs-environment-{}", std::process::id());
    let path = root
        .strip_prefix(hierarchy.root().expect("get the unified mount point"))
        .expect("delegated directory must be within the hierarchy mount")
        .join(&name);
    let cgroup = Cgroup::builder(hierarchy, CgroupPath::new(path).unwrap())
        .controllers(ControllerSelection::Only(vec!["pids".to_string()]))
        .create()
        .expect("create a child cgroup");
    assert!(cgroup.exists(), "new child cgroup must exist");
    let cgroup_type =
        fs::read_to_string(root.join(&name).join("cgroup.type")).expect("read child cgroup.type");
    assert_eq!(
        cgroup_type.trim(),
        "domain",
        "new child cgroup must be a valid domain"
    );

    let pids: &PidController = cgroup
        .controller_of()
        .expect("child cgroup must expose the pids controller");
    let limit = MaxValue::Value(16);
    pids.set_pid_max(limit).expect("set child cgroup pids.max");
    assert_eq!(
        pids.get_pid_max().expect("read child cgroup pids.max"),
        limit,
        "child cgroup must preserve its configured pids.max"
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

    prepare_parent_for_pids(&delegated_root);
    exercise_v2_hierarchy(
        Arc::new(DelegatedV2Hierarchy::new(delegated_root.clone())),
        &delegated_root,
    );
    // The built-in hierarchy starts at the actual mount point. A rootless
    // caller must traverse pre-enabled ancestors without writing to them.
    let hierarchy = hierarchies::auto().expect("discover the built-in hierarchy");
    assert_ne!(hierarchy.root().unwrap(), delegated_root);
    exercise_v2_hierarchy(hierarchy, &delegated_root);
}

#[test]
#[ignore]
fn cgroup_namespace_nested_v2() {
    cgroups_rs::skip_if_not_root!();

    assert_eq!(
        current_v2_path(),
        "/",
        "the service cgroup must become the cgroup namespace root"
    );
    assert!(
        hierarchies::is_cgroup2_unified_mode().unwrap(),
        "the private /sys/fs/cgroup mount must be cgroup2"
    );

    let (mount_root, mount_point) = live_cgroup2_mount();
    assert_eq!(mount_root, PathBuf::from("/"));
    assert_eq!(mount_point, PathBuf::from("/sys/fs/cgroup"));

    let root_pids = prepare_parent_for_pids(Path::new("/sys/fs/cgroup"));
    let test_pid = std::process::id().to_string();
    assert!(
        root_pids.iter().any(|pid| pid != &test_pid),
        "the unshare --fork waiting parent must be moved out of the namespace root"
    );
    exercise_v2_hierarchy(hierarchies::auto().unwrap(), Path::new("/sys/fs/cgroup"));
}
