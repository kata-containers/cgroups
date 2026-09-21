// Copyright (c) 2018 Levente Kurusa
// Copyright (c) 2020 Ant Group
//
// SPDX-License-Identifier: Apache-2.0 or MIT
//

//! This module contains the implementation of the `cpuset` cgroup subsystem.
//!
//! See the Kernel's documentation for more information about this subsystem, found at:
//!  [Documentation/cgroup-v1/cpusets.txt](https://www.kernel.org/doc/Documentation/cgroup-v1/cpusets.txt)

use log::*;
use std::path::{Path, PathBuf};

use crate::fs::error::ErrorKind::*;
use crate::fs::error::*;

use crate::fs::optional_read;
use crate::fs::{
    ControllIdentifier, ControllerInternal, Controllers, CpuResources, Resources, Subsystem,
};

/// A controller that allows controlling the `cpuset` subsystem of a Cgroup.
///
/// In essence, this controller is responsible for restricting the tasks in the control group to a
/// set of CPUs and/or memory nodes.
#[derive(Debug, Clone)]
pub struct CpuSetController {
    base: PathBuf,
    path: PathBuf,
    v2: bool,
    // Retain the v2 hierarchy root when entering children, including when
    // the hierarchy factory leaves the legacy base coordinate empty.
    v2_root: Option<PathBuf>,
}

/// The current state of the `cpuset` controller for this control group.
#[derive(Debug, PartialEq, Eq, Clone, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CpuSet {
    /// If true, no other control groups can share the CPUs listed in the `cpus` field.
    pub cpu_exclusive: bool,
    /// The list of CPUs the tasks of the control group can run on.
    ///
    /// This is a vector of `(start, end)` tuples, where each tuple is a range of CPUs where the
    /// control group is allowed to run on. Both sides of the range are inclusive.
    pub cpus: Vec<(u64, u64)>,
    /// The list of CPUs that the tasks can effectively run on. This removes the list of CPUs that
    /// the parent (and all of its parents) cannot run on from the `cpus` field of this control
    /// group.
    pub effective_cpus: Vec<(u64, u64)>,
    /// The list of memory nodes that the tasks can effectively use. This removes the list of nodes that
    /// the parent (and all of its parents) cannot use from the `mems` field of this control
    /// group.
    pub effective_mems: Vec<(u64, u64)>,
    /// If true, no other control groups can share the memory nodes listed in the `mems` field.
    pub mem_exclusive: bool,
    /// If true, the control group is 'hardwalled'. Kernel memory allocations (except for a few
    /// minor exceptions) are made from the memory nodes designated in the `mems` field.
    pub mem_hardwall: bool,
    /// If true, whenever `mems` is changed via `set_mems()`, the memory stored on the previous
    /// nodes are migrated to the new nodes selected by the new `mems`.
    pub memory_migrate: bool,
    /// Running average of the memory pressured faced by the tasks in the control group.
    pub memory_pressure: u64,
    /// This field is only at the root control group and controls whether the kernel will compute
    /// the memory pressure for control groups or not.
    pub memory_pressure_enabled: Option<bool>,
    /// If true, filesystem buffers are spread across evenly between the nodes specified in `mems`.
    pub memory_spread_page: bool,
    /// If true, kernel slab caches for file I/O are spread across evenly between the nodes
    /// specified in `mems`.
    pub memory_spread_slab: bool,
    /// The list of memory nodes the tasks of the control group can use.
    ///
    /// The format is the same as the `cpus`, `effective_cpus` and `effective_mems` fields.
    pub mems: Vec<(u64, u64)>,
    /// If true, the kernel will attempt to rebalance the load between the CPUs specified in the
    /// `cpus` field of this control group.
    pub sched_load_balance: bool,
    /// Represents how much work the kernel should do to rebalance this cpuset.
    ///
    /// `None` means the interface is unavailable, including on cgroup v2.
    /// When present, the value controls the search range on scheduling events:
    ///
    /// | `sched_relax_domain_level` | Effect |
    /// | -------------------- | ------ |
    /// |          -1          | No request; use the system default or another cpuset's request |
    /// |           0          | No search |
    /// |           1          | Search sibling threads in the same core |
    /// |           2          | Search cores in the same CPU package |
    /// |           3          | Search CPUs in the same node |
    /// |           4          | Search nodes in the same chunk of nodes |
    /// |           5          | Search system-wide |
    ///
    /// Levels depend on the architecture and kernel configuration; see the
    /// [kernel documentation](https://docs.kernel.org/admin-guide/cgroup-v1/cpusets.html#what-is-sched-relax-domain-level).
    pub sched_relax_domain_level: Option<i64>,
}

impl ControllerInternal for CpuSetController {
    fn control_type(&self) -> Controllers {
        Controllers::CpuSet
    }
    fn get_path(&self) -> &PathBuf {
        &self.path
    }
    fn get_path_mut(&mut self) -> &mut PathBuf {
        &mut self.path
    }
    fn get_base(&self) -> &PathBuf {
        &self.base
    }

    fn is_v2(&self) -> bool {
        self.v2
    }

    fn apply(&self, res: &Resources) -> Result<()> {
        // get the resources that apply to this controller
        let res: &CpuResources = &res.cpu;

        if let Some(cpus) = &res.cpus {
            self.set_cpus(cpus)?;
        }
        if let Some(mems) = &res.mems {
            self.set_mems(mems)?;
        }

        Ok(())
    }

    fn post_create(&self) {
        if self.is_v2() {
            return;
        }
        let current = self.get_path();

        if current != self.get_base() {
            match copy_from_parent(current, "cpuset.cpus") {
                Ok(_) => (),
                Err(err) => error!("error create_dir for cpuset.cpus {:?}", err),
            }
            match copy_from_parent(current, "cpuset.mems") {
                Ok(_) => (),
                Err(err) => error!("error create_dir for cpuset.mems {:?}", err),
            }
        }
    }
}

fn find_no_empty_parent(from: &Path, file: &str) -> Result<(String, Vec<PathBuf>)> {
    let mut current_path = from.to_path_buf();
    let mut v = vec![];

    loop {
        let current_value = match ::std::fs::read_to_string(current_path.join(file)) {
            Ok(cpus) => String::from(cpus.trim()),
            Err(e) => {
                return Err(Error::with_cause(
                    ReadFailed(current_path.display().to_string()),
                    e,
                ))
            }
        };

        if !current_value.is_empty() {
            return Ok((current_value, v));
        }
        v.push(current_path.clone());

        let parent = match current_path.parent() {
            Some(p) => p,
            None => return Ok(("".to_string(), v)),
        };

        // next loop, find parent
        current_path = parent.to_path_buf();
    }
}

/// copy_from_parent copy the cpuset.cpus and cpuset.mems from the parent
/// directory to the current directory if the file's contents are 0
fn copy_from_parent(current: &Path, file: &str) -> Result<()> {
    // find not empty cpus/memes from current directory.
    let (value, parents) = find_no_empty_parent(current, file)?;

    if value.is_empty() || parents.is_empty() {
        return Ok(());
    }

    for p in parents.iter().rev() {
        let mut pb = p.clone();
        pb.push(file);
        match ::std::fs::write(&pb, value.as_bytes()) {
            Ok(_) => (),
            Err(e) => {
                return Err(Error::with_cause(
                    WriteFailed(pb.display().to_string(), pb.display().to_string()),
                    e,
                ))
            }
        }
    }

    Ok(())
}

impl ControllIdentifier for CpuSetController {
    fn controller_type() -> Controllers {
        Controllers::CpuSet
    }
}

impl<'a> From<&'a Subsystem> for &'a CpuSetController {
    fn from(sub: &'a Subsystem) -> &'a CpuSetController {
        unsafe {
            match sub {
                Subsystem::CpuSet(c) => c,
                _ => {
                    assert_eq!(1, 0);
                    let v = std::mem::MaybeUninit::uninit();
                    v.assume_init()
                }
            }
        }
    }
}

/// Parse a string like "1,2,4-5,8" into a list of (start, end) tuples.
fn parse_range(s: String) -> Result<Vec<(u64, u64)>> {
    let mut fin = Vec::new();

    if s.is_empty() {
        return Ok(fin);
    }

    // first split by commas
    let comma_split = s.split(',');

    for sp in comma_split {
        if sp.contains('-') {
            // this is a true range
            let dash_split = sp.split('-').collect::<Vec<_>>();
            if dash_split.len() != 2 {
                return Err(Error::new(ParseError));
            }
            let first = dash_split[0].parse::<u64>();
            let second = dash_split[1].parse::<u64>();
            if first.is_err() || second.is_err() {
                return Err(Error::new(ParseError));
            }
            fin.push((first.unwrap(), second.unwrap()));
        } else {
            // this is just a single number
            let num = sp.parse::<u64>();
            if num.is_err() {
                return Err(Error::new(ParseError));
            }
            fin.push((num.clone().unwrap(), num.clone().unwrap()));
        }
    }

    Ok(fin)
}

impl CpuSetController {
    /// Contructs a new `CpuSetController` with `root` serving as the root of the control group.
    ///
    /// On v2, an empty `root` treats `point` as the hierarchy root. When
    /// constructing a child directly, pass its hierarchy root explicitly so
    /// configured CPU and memory-node masks remain required for that child.
    pub fn new(point: PathBuf, root: PathBuf, v2: bool) -> Self {
        let v2_root = v2.then(|| {
            if root.as_os_str().is_empty() {
                point.clone()
            } else {
                root.clone()
            }
        });
        Self {
            base: root,
            path: point,
            v2,
            v2_root,
        }
    }

    /// Returns the statistics gathered by the kernel for this control group, or an error if reading failed.
    ///
    /// On cgroup v2, the v1-only fields `cpu_exclusive`, `mem_exclusive`,
    /// `mem_hardwall`, `memory_migrate`, `memory_spread_page`, `memory_spread_slab`,
    /// and `sched_load_balance` return `false`, and `memory_pressure` returns `0`.
    /// These are compatibility defaults for unavailable v1 interfaces.
    /// `sched_relax_domain_level` and `memory_pressure_enabled` instead return
    /// `None` when their files are absent. Other I/O errors and malformed values
    /// are propagated.
    ///
    /// At the v2 hierarchy root, absent `cpuset.cpus` and `cpuset.mems`
    /// yield empty configured lists; their effective masks are then required.
    /// Configured masks remain required for v1 and for v2 children.
    pub fn cpuset(&self) -> Result<CpuSet> {
        let effective_cpus = if self.v2 {
            "cpuset.cpus.effective"
        } else {
            "cpuset.effective_cpus"
        };
        let effective_mems = if self.v2 {
            "cpuset.mems.effective"
        } else {
            "cpuset.effective_mems"
        };
        let read_range = |name| self.read_value(name, |input| parse_range(input.to_owned()));
        let read_masks = |configured, effective| -> Result<_> {
            match read_range(configured) {
                Ok(mask) => Ok((mask, optional_read(read_range(effective))?)),
                Err(error)
                    if self.v2_root.as_deref() == Some(self.path.as_path())
                        && error.is_not_found() =>
                {
                    // Root has no configurable mask. Require the effective
                    // interface so a removed or unavailable cpuset still fails.
                    Ok((Vec::new(), read_range(effective)?))
                }
                Err(error) => Err(error),
            }
        };
        let (cpus, effective_cpus) = read_masks("cpuset.cpus", effective_cpus)?;
        let (mems, effective_mems) = read_masks("cpuset.mems", effective_mems)?;
        Ok(CpuSet {
            cpu_exclusive: {
                optional_read(
                    self.read_value("cpuset.cpu_exclusive", str::parse::<u64>)
                        .map(|x| x == 1),
                )?
            },
            cpus,
            effective_cpus,
            effective_mems,
            mem_exclusive: {
                optional_read(
                    self.read_value("cpuset.mem_exclusive", str::parse::<u64>)
                        .map(|x| x == 1),
                )?
            },
            mem_hardwall: {
                optional_read(
                    self.read_value("cpuset.mem_hardwall", str::parse::<u64>)
                        .map(|x| x == 1),
                )?
            },
            memory_migrate: {
                optional_read(
                    self.read_value("cpuset.memory_migrate", str::parse::<u64>)
                        .map(|x| x == 1),
                )?
            },
            memory_pressure: {
                optional_read(self.read_value("cpuset.memory_pressure", str::parse::<u64>))?
            },
            memory_pressure_enabled: {
                optional_read(
                    self.read_value("cpuset.memory_pressure_enabled", str::parse::<u64>)
                        .map(|x| Some(x == 1)),
                )?
            },
            memory_spread_page: {
                optional_read(
                    self.read_value("cpuset.memory_spread_page", str::parse::<u64>)
                        .map(|x| x == 1),
                )?
            },
            memory_spread_slab: {
                optional_read(
                    self.read_value("cpuset.memory_spread_slab", str::parse::<u64>)
                        .map(|x| x == 1),
                )?
            },
            mems,
            sched_load_balance: {
                optional_read(
                    self.read_value("cpuset.sched_load_balance", str::parse::<u64>)
                        .map(|x| x == 1),
                )?
            },
            sched_relax_domain_level: {
                optional_read(
                    self.read_value("cpuset.sched_relax_domain_level", str::parse::<i64>)
                        .map(Some),
                )?
            },
        })
    }

    /// Control whether the CPUs selected via `set_cpus()` should be exclusive to this control
    /// group or not.
    pub fn set_cpu_exclusive(&self, b: bool) -> Result<()> {
        self.write_value("cpuset.cpu_exclusive", if b { "1" } else { "0" })
    }

    /// Control whether the memory nodes selected via `set_memss()` should be exclusive to this control
    /// group or not.
    pub fn set_mem_exclusive(&self, b: bool) -> Result<()> {
        self.write_value("cpuset.mem_exclusive", if b { "1" } else { "0" })
    }

    /// Set the CPUs that the tasks in this control group can run on.
    ///
    /// Syntax is a comma separated list of CPUs, with an additional extension that ranges can
    /// be represented via dashes.
    pub fn set_cpus(&self, cpus: &str) -> Result<()> {
        self.write_value("cpuset.cpus", cpus)
    }

    /// Set the memory nodes that the tasks in this control group can use.
    ///
    /// Syntax is the same as with `set_cpus()`.
    pub fn set_mems(&self, mems: &str) -> Result<()> {
        self.write_value("cpuset.mems", mems)
    }

    /// Controls whether the control group should be "hardwalled", i.e., whether kernel allocations
    /// should exclusively use the memory nodes set via `set_mems()`.
    ///
    /// Note that some kernel allocations, most notably those that are made in interrupt handlers
    /// may disregard this.
    pub fn set_hardwall(&self, b: bool) -> Result<()> {
        self.write_value("cpuset.mem_hardwall", if b { "1" } else { "0" })
    }

    /// Controls whether the kernel should attempt to rebalance the load between the CPUs specified in the
    /// `cpus` field of this control group.
    pub fn set_load_balancing(&self, b: bool) -> Result<()> {
        self.write_value("cpuset.sched_load_balance", if b { "1" } else { "0" })
    }

    /// Contorl how much effort the kernel should invest in rebalacing the control group.
    ///
    /// See @CpuSet 's similar field for more information.
    pub fn set_rebalance_relax_domain_level(&self, i: i64) -> Result<()> {
        self.write_value("cpuset.sched_relax_domain_level", &i.to_string())
    }

    /// Control whether when using `set_mems()` the existing memory used by the tasks should be
    /// migrated over to the now-selected nodes.
    pub fn set_memory_migration(&self, b: bool) -> Result<()> {
        self.write_value("cpuset.memory_migrate", if b { "1" } else { "0" })
    }

    /// Control whether filesystem buffers should be evenly split across the nodes selected via
    /// `set_mems()`.
    pub fn set_memory_spread_page(&self, b: bool) -> Result<()> {
        self.write_value("cpuset.memory_spread_page", if b { "1" } else { "0" })
    }

    /// Control whether the kernel's slab cache for file I/O should be evenly split across the
    /// nodes selected via `set_mems()`.
    pub fn set_memory_spread_slab(&self, b: bool) -> Result<()> {
        self.write_value("cpuset.memory_spread_slab", if b { "1" } else { "0" })
    }

    /// Control whether the kernel should collect information to calculate memory pressure for
    /// control groups.
    ///
    /// Note: This will fail with `InvalidOperation` if the current congrol group is not the root
    /// control group.
    pub fn set_enable_memory_pressure(&self, b: bool) -> Result<()> {
        if !self.path_exists("cpuset.memory_pressure_enabled") {
            return Err(Error::new(InvalidOperation));
        }
        self.write_value("cpuset.memory_pressure_enabled", if b { "1" } else { "0" })
    }
}

#[cfg(test)]
mod tests {
    use crate::fs::cpuset::{self, CpuSetController};
    use crate::fs::error::{ErrorKind, ParsePidFileError, ReadFileError, WriteFileError};
    use crate::fs::{Controller, CpuResources, Resources};
    use crate::tests::TestDir;
    use std::error::Error as _;
    use std::fs::{self, File};
    use std::io::Write;
    use std::path::PathBuf;

    fn cpuset_fixture() -> TestDir {
        let dir = TestDir::new("cpuset");
        fs::write(dir.path().join("cpuset.cpus"), "0-1\n").unwrap();
        fs::write(dir.path().join("cpuset.mems"), "0\n").unwrap();
        dir
    }

    #[test]
    fn test_cpuset_read_errors_preserve_path_input_and_source() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let fixture = TestDir::new("cpuset_read_context");
        let dir = fixture.join(OsStr::from_bytes(b"group-\xff"));
        fs::create_dir(&dir).unwrap();
        let controller = CpuSetController::new(dir.clone(), dir.clone(), false);
        let error = controller.cpuset().unwrap_err();
        assert!(matches!(
            error.source().unwrap().downcast_ref::<ReadFileError>().unwrap(),
            ReadFileError::Open { path, cause }
                if path == &dir.join("cpuset.cpus") && cause.raw_os_error() == Some(libc::ENOENT)
        ));
        fs::write(dir.join("cpuset.cpus"), "0-1\n").unwrap();
        fs::write(dir.join("cpuset.mems"), "0\n").unwrap();

        for (name, valid) in [("cpuset.cpus", "0-1\n"), ("cpuset.cpu_exclusive", "0\n")] {
            let path = dir.join(name);
            fs::write(&path, " invalid\n").unwrap();
            let error = controller.cpuset().unwrap_err();
            assert_eq!(error.kind(), &ErrorKind::ParseError);
            assert!(error.to_string().contains(name));
            let ReadFileError::Parse {
                path: target,
                input,
                cause,
            } = error
                .source()
                .unwrap()
                .downcast_ref::<ReadFileError>()
                .unwrap()
            else {
                panic!("expected contextual parse error");
            };
            assert_eq!(target, &path);
            assert_eq!(input, " invalid\n");
            if name == "cpuset.cpu_exclusive" {
                assert!(cause.downcast_ref::<std::num::ParseIntError>().is_some());
            }

            fs::remove_file(&path).unwrap();
            fs::create_dir(&path).unwrap();
            let error = controller.cpuset().unwrap_err();
            assert_eq!(
                error.kind(),
                &ErrorKind::ReadFailed(path.display().to_string())
            );
            assert!(error.to_string().contains(name));
            assert!(matches!(
                error.source().unwrap().downcast_ref::<ReadFileError>().unwrap(),
                ReadFileError::Read { path: target, cause }
                    if target == &path && cause.raw_os_error() == Some(libc::EISDIR)
            ));
            fs::remove_dir(&path).unwrap();
            fs::write(&path, valid).unwrap();
        }
    }

    #[test]
    fn test_cpuset_v2_root_without_configured_masks() {
        use crate::core::{CgroupPath, CgroupVersion};
        use crate::fs::{hierarchies, Cgroup};

        let fixture = crate::tests::topology_fixture(CgroupVersion::V2, "cpuset");
        let root = fixture.topology.fixture_root().unwrap();
        fs::write(root.join("cpuset.cpus.effective"), "0-3\n").unwrap();
        fs::write(root.join("cpuset.mems.effective"), "1\n").unwrap();
        let hierarchy = hierarchies::from_topology(fixture.topology.clone());
        let cgroup = Cgroup::load(hierarchy.clone(), CgroupPath::root());
        let controller: &CpuSetController = cgroup.controller_of().unwrap();

        let stats = controller.clone().cpuset().unwrap();
        assert!(stats.cpus.is_empty());
        assert!(stats.mems.is_empty());
        assert_eq!(stats.effective_cpus, [(0, 3)]);
        assert_eq!(stats.effective_mems, [(1, 1)]);

        // Entering a child must retain strict configured-mask reads.
        let child = Cgroup::load(hierarchy, CgroupPath::new("child").unwrap());
        let controller: &CpuSetController = child.controller_of().unwrap();
        fs::create_dir(controller.path()).unwrap();
        fs::write(controller.path().join("cpuset.cpus.effective"), "0-1\n").unwrap();
        fs::write(controller.path().join("cpuset.mems.effective"), "1\n").unwrap();
        for file in ["cpuset.cpus", "cpuset.mems"] {
            let path = controller.path().join(file);
            let error = controller.cpuset().unwrap_err();
            assert_eq!(
                error.kind(),
                &ErrorKind::ReadFailed(path.display().to_string())
            );
            assert!(error.is_not_found());
            fs::write(path, "0\n").unwrap();
        }
        assert_eq!(controller.cpuset().unwrap().cpus, [(0, 0)]);
    }

    #[test]
    fn test_cpuset_v2_root_preserves_mask_read_errors() {
        let dir = TestDir::new("cpuset_v2_root");
        let controller = CpuSetController::new(dir.to_path_buf(), dir.to_path_buf(), true);
        for (configured, effective) in [
            ("cpuset.cpus", "cpuset.cpus.effective"),
            ("cpuset.mems", "cpuset.mems.effective"),
        ] {
            fs::write(dir.join(effective), "0\n").unwrap();
            fs::write(dir.join(configured), "0\n").unwrap();
        }

        for (configured, effective) in [
            ("cpuset.cpus", "cpuset.cpus.effective"),
            ("cpuset.mems", "cpuset.mems.effective"),
        ] {
            let path = dir.join(configured);
            fs::write(&path, "invalid\n").unwrap();
            assert_eq!(
                controller.cpuset().unwrap_err().kind(),
                &ErrorKind::ParseError
            );
            fs::remove_file(&path).unwrap();
            fs::create_dir(&path).unwrap();
            let error = controller.cpuset().unwrap_err();
            assert_eq!(
                error
                    .source()
                    .unwrap()
                    .downcast_ref::<ReadFileError>()
                    .unwrap()
                    .source()
                    .unwrap()
                    .downcast_ref::<std::io::Error>()
                    .unwrap()
                    .raw_os_error(),
                Some(libc::EISDIR)
            );
            fs::remove_dir(&path).unwrap();

            // An absent configured mask does not make its effective mask optional.
            fs::remove_file(dir.join(effective)).unwrap();
            let error = controller.cpuset().unwrap_err();
            assert_eq!(
                error.kind(),
                &ErrorKind::ReadFailed(dir.join(effective).display().to_string())
            );
            assert!(error.is_not_found());
            fs::write(dir.join(effective), "invalid\n").unwrap();
            assert_eq!(
                controller.cpuset().unwrap_err().kind(),
                &ErrorKind::ParseError
            );
            fs::write(dir.join(effective), "0\n").unwrap();
            fs::write(&path, "0\n").unwrap();
        }
    }

    #[test]
    fn test_cpuset_required_files_and_invalid_masks_propagate() {
        use std::error::Error as _;

        let dir = cpuset_fixture();
        let controller =
            CpuSetController::new(dir.path().to_path_buf(), dir.path().to_path_buf(), false);
        for file in ["cpuset.cpus", "cpuset.mems"] {
            let path = dir.path().join(file);
            let contents = fs::read(&path).unwrap();
            fs::remove_file(&path).unwrap();
            let error = controller.cpuset().unwrap_err();
            assert_eq!(
                error.kind(),
                &ErrorKind::ReadFailed(path.display().to_string())
            );
            assert_eq!(
                error
                    .source()
                    .unwrap()
                    .downcast_ref::<ReadFileError>()
                    .unwrap()
                    .source()
                    .unwrap()
                    .downcast_ref::<std::io::Error>()
                    .unwrap()
                    .kind(),
                std::io::ErrorKind::NotFound
            );

            fs::write(&path, "invalid\n").unwrap();
            assert_eq!(
                controller.cpuset().unwrap_err().kind(),
                &ErrorKind::ParseError
            );
            fs::write(&path, contents).unwrap();
        }
    }

    #[test]
    fn test_cpuset_preserves_present_relax_domain_levels() {
        let dir = cpuset_fixture();
        fs::write(dir.path().join("cpuset.effective_cpus"), "0-1\n").unwrap();
        fs::write(dir.path().join("cpuset.effective_mems"), "0\n").unwrap();
        let controller =
            CpuSetController::new(dir.path().to_path_buf(), dir.path().to_path_buf(), false);

        for level in [-1, 0, 2] {
            fs::write(
                dir.path().join("cpuset.sched_relax_domain_level"),
                format!("{}\n", level),
            )
            .unwrap();

            let stats = controller.cpuset().unwrap();
            assert_eq!(stats.sched_relax_domain_level, Some(level));
            assert_eq!(stats.effective_cpus, vec![(0, 1)]);
            assert_eq!(stats.effective_mems, vec![(0, 0)]);
        }
    }

    #[test]
    fn test_cpuset_missing_relax_domain_level_is_none() {
        let dir = cpuset_fixture();
        for v2 in [false, true] {
            let controller =
                CpuSetController::new(dir.path().to_path_buf(), dir.path().to_path_buf(), v2);
            let stats = controller.cpuset().unwrap();
            assert_eq!(stats.sched_relax_domain_level, None);
            assert_eq!(stats.memory_pressure_enabled, None);
        }
    }

    #[test]
    fn test_cpuset_relax_domain_level_errors_propagate() {
        use std::error::Error as _;

        let dir = cpuset_fixture();
        let path = dir.path().join("cpuset.sched_relax_domain_level");
        let controller =
            CpuSetController::new(dir.path().to_path_buf(), dir.path().to_path_buf(), false);

        fs::write(&path, "invalid\n").unwrap();
        assert_eq!(
            controller.cpuset().unwrap_err().kind(),
            &ErrorKind::ParseError
        );

        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        let error = controller.cpuset().unwrap_err();
        assert!(matches!(error.kind(), ErrorKind::ReadFailed(_)));
        let cause = error
            .source()
            .unwrap()
            .downcast_ref::<ReadFileError>()
            .unwrap()
            .source()
            .unwrap()
            .downcast_ref::<std::io::Error>()
            .unwrap();
        assert_eq!(cause.raw_os_error(), Some(libc::EISDIR));
    }

    #[test]
    fn test_cpuset_reads_v2_effective_masks_for_inherited_settings() {
        let dir = cpuset_fixture();
        fs::write(dir.path().join("cpuset.cpus"), "\n").unwrap();
        fs::write(dir.path().join("cpuset.mems"), "\n").unwrap();
        fs::write(dir.path().join("cpuset.cpus.effective"), "2-3\n").unwrap();
        fs::write(dir.path().join("cpuset.mems.effective"), "1\n").unwrap();
        // V1 filenames must not be consulted on v2.
        fs::write(dir.path().join("cpuset.effective_cpus"), "invalid\n").unwrap();
        fs::write(dir.path().join("cpuset.effective_mems"), "invalid\n").unwrap();
        let controller =
            CpuSetController::new(dir.path().to_path_buf(), dir.path().to_path_buf(), true);

        let stats = controller.cpuset().unwrap();
        assert!(stats.cpus.is_empty());
        assert!(stats.mems.is_empty());
        assert_eq!(stats.effective_cpus, vec![(2, 3)]);
        assert_eq!(stats.effective_mems, vec![(1, 1)]);

        fs::write(dir.path().join("cpuset.cpus.effective"), "invalid\n").unwrap();
        assert_eq!(
            controller.cpuset().unwrap_err().kind(),
            &ErrorKind::ParseError
        );
    }

    #[test]
    fn test_parse_range() {
        let test_cases = vec![
            "1,2,4-6,9".to_string(),
            "".to_string(),
            "1".to_string(),
            "1-111".to_string(),
            "1,2,3,4".to_string(),
            "1-5,6-7,8-9".to_string(),
        ];
        let expecteds = [
            vec![(1, 1), (2, 2), (4, 6), (9, 9)],
            vec![],
            vec![(1, 1)],
            vec![(1, 111)],
            vec![(1, 1), (2, 2), (3, 3), (4, 4)],
            vec![(1, 5), (6, 7), (8, 9)],
        ];

        for (i, case) in test_cases.into_iter().enumerate() {
            let range = cpuset::parse_range(case.clone());
            println!("{:?} => {:?}", case, range);
            assert!(range.is_ok());
            assert_eq!(range.unwrap(), expecteds[i]);
        }
    }

    #[test]
    fn test_cpuset_defaults_only_missing_optional_files() {
        let dir = cpuset_fixture();
        let path = dir.path();
        let controller = CpuSetController::new(path.to_path_buf(), PathBuf::new(), true);

        let stats = controller.cpuset().unwrap();
        assert_eq!(stats.cpus, vec![(0, 1)]);
        assert!(!stats.cpu_exclusive);

        fs::write(path.join("cpuset.cpu_exclusive"), "invalid\n").unwrap();
        assert_eq!(
            controller.cpuset().unwrap_err().kind(),
            &ErrorKind::ParseError
        );
    }

    #[test]
    fn test_apply_write_failure_preserves_non_utf8_path_and_errno() {
        use std::ffi::OsStr;
        use std::os::unix::{ffi::OsStrExt, fs::symlink};

        let fixture = TestDir::new("write_context");
        let dir = fixture.path().join(OsStr::from_bytes(b"group-\xff"));
        fs::create_dir(&dir).unwrap();
        let mems_path = dir.join("cpuset.mems");
        let controller = CpuSetController::new(dir.to_path_buf(), dir.to_path_buf(), false);
        let resources = Resources {
            cpu: CpuResources {
                cpus: Some("0-1".into()),
                mems: Some("0".into()),
                ..Default::default()
            },
            ..Default::default()
        };

        // A dangling target fails during open; /dev/full opens but rejects writes.
        for (target, errno) in [
            (dir.join("missing/cpuset.mems"), libc::ENOENT),
            (PathBuf::from("/dev/full"), libc::ENOSPC),
        ] {
            symlink(target, &mems_path).unwrap();
            let error = controller.apply(&resources).unwrap_err();
            assert_eq!(
                error.kind(),
                &ErrorKind::WriteFailed("cpuset.mems".into(), "0".into())
            );
            let source = error
                .source()
                .unwrap()
                .downcast_ref::<WriteFileError>()
                .unwrap();
            let path = match source {
                WriteFileError::Open { path, .. } if errno == libc::ENOENT => path,
                WriteFileError::Write { path, .. } if errno == libc::ENOSPC => path,
                other => panic!("unexpected write failure stage: {:?}", other),
            };
            assert_eq!(
                path.as_os_str().as_bytes(),
                mems_path.as_os_str().as_bytes()
            );
            assert_eq!(
                source
                    .source()
                    .unwrap()
                    .downcast_ref::<std::io::Error>()
                    .unwrap()
                    .raw_os_error(),
                Some(errno)
            );
            assert_eq!(fs::read_to_string(dir.join("cpuset.cpus")).unwrap(), "0-1");
            fs::remove_file(&mems_path).unwrap();
        }
    }

    #[test]
    fn test_apply_stops_after_first_write_failure() {
        let fixture = TestDir::new("apply_write_failure");
        let dir = fixture.path();

        // Opening a directory for writing fails with EISDIR even as root.
        let cpus_path = dir.join("cpuset.cpus");
        fs::create_dir(&cpus_path).unwrap();

        let mems_path = dir.join("cpuset.mems");
        fs::write(&mems_path, "1").unwrap();

        let controller = CpuSetController::new(dir.to_path_buf(), dir.to_path_buf(), false);

        let resources = Resources {
            cpu: CpuResources {
                cpus: Some("0-1".to_string()),
                mems: Some("0".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };

        let err = controller.apply(&resources).unwrap_err();
        assert_eq!(
            err.kind(),
            &ErrorKind::WriteFailed("cpuset.cpus".into(), "0-1".into())
        );

        match err
            .source()
            .unwrap()
            .downcast_ref::<WriteFileError>()
            .unwrap()
        {
            WriteFileError::Open { path, cause } => {
                assert_eq!(path, &cpus_path);
                assert_eq!(cause.raw_os_error(), Some(libc::EISDIR));
            }
            other => panic!("expected open failure, got {:?}", other),
        }

        assert_eq!(fs::read_to_string(&mems_path).unwrap(), "1");
    }

    #[test]
    fn test_membership_read_failures_are_not_empty_lists() {
        let fixture = TestDir::new("membership_read_failure");
        let dir = fixture.path();

        // Directories open for reading, but reading their contents as bytes
        // fails with EISDIR even as root.
        let procs_path = dir.join("cgroup.procs");
        let tasks_path = dir.join("tasks");
        fs::create_dir(&procs_path).unwrap();
        fs::create_dir(&tasks_path).unwrap();

        let controller = CpuSetController::new(dir.to_path_buf(), dir.to_path_buf(), false);
        for (path, result) in [
            (&procs_path, controller.procs()),
            (&tasks_path, controller.tasks()),
        ] {
            let err =
                result.expect_err("membership read must fail on a directory, not return empty");
            assert_eq!(
                err.kind(),
                &ErrorKind::ReadFailed(path.display().to_string())
            );
            assert_eq!(
                err.source()
                    .unwrap()
                    .downcast_ref::<std::io::Error>()
                    .unwrap()
                    .raw_os_error(),
                Some(libc::EISDIR)
            );
        }
    }

    #[test]
    fn test_membership_reads_return_valid_pids_when_readable() {
        let fixture = TestDir::new("read_success");
        let dir = fixture.path();

        let procs_path = dir.join("cgroup.procs");
        {
            let mut f = File::create(&procs_path).unwrap();
            writeln!(f, "100").unwrap();
            writeln!(f, "200").unwrap();
        }

        let controller = CpuSetController::new(dir.to_path_buf(), dir.to_path_buf(), false);
        let procs = controller
            .procs()
            .expect("reading valid procs should succeed");
        assert_eq!(procs.len(), 2);
        assert_eq!(procs[0].pid, 100);
        assert_eq!(procs[1].pid, 200);
    }

    #[test]
    fn test_membership_parse_errors_preserve_path_record_line_and_source() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let fixture = TestDir::new("membership_parse");
        let dir = fixture.path().join(OsStr::from_bytes(b"cgroup-\xff"));
        fs::create_dir(&dir).unwrap();
        for (v2, file) in [
            (false, "cgroup.procs"),
            (false, "tasks"),
            (true, "cgroup.threads"),
        ] {
            let path = dir.join(file);
            fs::write(&path, "100\n bad-pid \n200\n").unwrap();
            let controller = CpuSetController::new(dir.to_path_buf(), dir.to_path_buf(), v2);
            let err = if file == "cgroup.procs" {
                controller.procs()
            } else {
                controller.tasks()
            }
            .unwrap_err();
            assert_eq!(err.kind(), &ErrorKind::ParseError);
            let context = err
                .source()
                .unwrap()
                .downcast_ref::<ParsePidFileError>()
                .unwrap();
            assert_eq!(context.path, path);
            assert_eq!(context.cause.line, 2);
            assert_eq!(context.cause.input, " bad-pid ");
            assert!(context
                .cause
                .source()
                .unwrap()
                .is::<std::num::ParseIntError>());
        }
    }
}
