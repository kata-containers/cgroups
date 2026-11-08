// Copyright (c) 2018 Levente Kurusa
// Copyright (c) 2020 Ant Group
//
// SPDX-License-Identifier: Apache-2.0 or MIT
//

#![allow(clippy::unnecessary_unwrap)]

use std::collections::HashMap;
use std::fmt;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;

macro_rules! update_and_test {
    ($self:ident, $set_func:ident, $value:expr, $get_func:ident) => {
        if let Some(v) = $value {
            $self.$set_func(v)?;
            if $self.$get_func()? != v {
                return Err(Error::new(Other));
            }
        }
    };
}

// Preserve the released best-effort setter behavior.
// TODO: Remove this macro once all call sites propagate setter failures.
macro_rules! update {
    ($self:ident, $set_func:ident, $value:expr) => {
        if let Some(v) = $value {
            let _ = $self.$set_func(v);
        }
    };
}

pub mod blkio;
pub mod cgroup;
pub mod cpu;
pub mod cpuacct;
pub mod cpuset;
pub mod devices;
pub mod error;
pub mod events;
pub mod freezer;
pub mod hierarchies;
pub mod hugetlb;
pub mod memory;
pub mod net_cls;
pub mod net_prio;
pub mod perf_event;
pub mod pid;
pub mod rdma;
mod reader;
pub mod systemd;

use crate::fs::blkio::BlkIoController;
use crate::fs::cpu::CpuController;
use crate::fs::cpuacct::CpuAcctController;
use crate::fs::cpuset::CpuSetController;
use crate::fs::devices::DevicesController;
use crate::fs::error::ErrorKind::*;
use crate::fs::error::*;
use crate::fs::freezer::FreezerController;
use crate::fs::hugetlb::HugeTlbController;
use crate::fs::memory::MemController;
use crate::fs::net_cls::NetClsController;
use crate::fs::net_prio::NetPrioController;
use crate::fs::perf_event::PerfEventController;
use crate::fs::pid::PidController;
use crate::fs::rdma::RdmaController;
use crate::fs::systemd::SystemdController;

#[doc(inline)]
pub use crate::fs::cgroup::{Cgroup, CgroupBuilder, ControllerSelection};
#[doc(inline)]
pub use crate::fs::reader::CgroupReader;

/// Contains all the subsystems that are available in this crate.
#[derive(Debug, Clone)]
pub enum Subsystem {
    /// Controller for the `Pid` subsystem, see `PidController` for more information.
    Pid(PidController),
    /// Controller for the `Mem` subsystem, see `MemController` for more information.
    Mem(MemController),
    /// Controller for the `CpuSet subsystem, see `CpuSetController` for more information.
    CpuSet(CpuSetController),
    /// Controller for the `CpuAcct` subsystem, see `CpuAcctController` for more information.
    CpuAcct(CpuAcctController),
    /// Controller for the `Cpu` subsystem, see `CpuController` for more information.
    Cpu(CpuController),
    /// Controller for the `Devices` subsystem, see `DevicesController` for more information.
    Devices(DevicesController),
    /// Controller for the `Freezer` subsystem, see `FreezerController` for more information.
    Freezer(FreezerController),
    /// Controller for the `NetCls` subsystem, see `NetClsController` for more information.
    NetCls(NetClsController),
    /// Controller for the `BlkIo` subsystem, see `BlkIoController` for more information.
    BlkIo(BlkIoController),
    /// Controller for the `PerfEvent` subsystem, see `PerfEventController` for more information.
    PerfEvent(PerfEventController),
    /// Controller for the `NetPrio` subsystem, see `NetPrioController` for more information.
    NetPrio(NetPrioController),
    /// Controller for the `HugeTlb` subsystem, see `HugeTlbController` for more information.
    HugeTlb(HugeTlbController),
    /// Controller for the `Rdma` subsystem, see `RdmaController` for more information.
    Rdma(RdmaController),
    /// Controller for the `Systemd` subsystem, see `SystemdController` for more information.
    Systemd(SystemdController),
}

#[doc(hidden)]
#[derive(Eq, PartialEq, Debug, Clone)]
pub enum Controllers {
    Pids,
    Mem,
    CpuSet,
    CpuAcct,
    Cpu,
    Devices,
    Freezer,
    NetCls,
    BlkIo,
    PerfEvent,
    NetPrio,
    HugeTlb,
    Rdma,
    Systemd,
}

impl fmt::Display for Controllers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Controllers::Pids => write!(f, "pids"),
            Controllers::Mem => write!(f, "memory"),
            Controllers::CpuSet => write!(f, "cpuset"),
            Controllers::CpuAcct => write!(f, "cpuacct"),
            Controllers::Cpu => write!(f, "cpu"),
            Controllers::Devices => write!(f, "devices"),
            Controllers::Freezer => write!(f, "freezer"),
            Controllers::NetCls => write!(f, "net_cls"),
            Controllers::BlkIo => write!(f, "blkio"),
            Controllers::PerfEvent => write!(f, "perf_event"),
            Controllers::NetPrio => write!(f, "net_prio"),
            Controllers::HugeTlb => write!(f, "hugetlb"),
            Controllers::Rdma => write!(f, "rdma"),
            Controllers::Systemd => write!(f, "name=systemd"),
        }
    }
}

mod sealed {
    use super::*;

    pub(crate) trait ControllerInternal {
        fn apply(&self, res: &Resources) -> Result<()>;

        // meta stuff
        fn control_type(&self) -> Controllers;
        fn get_path(&self) -> &PathBuf;
        fn get_path_mut(&mut self) -> &mut PathBuf;
        fn get_base(&self) -> &PathBuf;

        /// Hooks running after controller crated, if have
        fn post_create(&self) {}

        fn is_v2(&self) -> bool {
            false
        }

        fn open_path(&self, p: &str, w: bool) -> Result<File> {
            let mut path = self.get_path().clone();
            path.push(p);

            if w {
                match File::create(&path) {
                    Err(e) => Err(Error::with_cause(
                        ErrorKind::WriteFailed(
                            path.display().to_string(),
                            "[CREATE FILE]".to_string(),
                        ),
                        e,
                    )),
                    Ok(file) => Ok(file),
                }
            } else {
                match File::open(&path) {
                    Err(e) => Err(Error::with_cause(
                        ErrorKind::ReadFailed(path.display().to_string()),
                        e,
                    )),
                    Ok(file) => Ok(file),
                }
            }
        }

        /// Read a resource value, attaching its path to I/O and parser failures.
        /// The parser receives trimmed text; parse errors retain the original input.
        fn read_value<T, E>(
            &self,
            name: &str,
            parser: impl FnOnce(&str) -> std::result::Result<T, E>,
        ) -> Result<T>
        where
            E: 'static + Send + Sync + std::error::Error,
        {
            let path = self.get_path().join(name);
            let mut file = File::open(&path).map_err(|cause| {
                Error::with_cause(
                    ReadFailed(path.display().to_string()),
                    ReadFileError::Open {
                        path: path.clone(),
                        cause,
                    },
                )
            })?;
            let mut input = String::new();
            file.read_to_string(&mut input).map_err(|cause| {
                Error::with_cause(
                    ReadFailed(path.display().to_string()),
                    ReadFileError::Read {
                        path: path.clone(),
                        cause,
                    },
                )
            })?;
            parser(input.trim()).map_err(|cause| {
                Error::with_cause(
                    ParseError,
                    ReadFileError::Parse {
                        path,
                        input,
                        cause: Box::new(cause),
                    },
                )
            })
        }

        /// Write one resource file, validating its name before opening it and
        /// retaining consistent context for open and write failures.
        fn write_value(&self, name: &str, value: &str) -> Result<()> {
            validate_attribute_name(name, "ControllerInternal::write_value")?;
            let path = self.get_path().join(name);
            let mut file = File::create(&path).map_err(|cause| {
                Error::with_cause(
                    WriteFailed(name.to_owned(), value.to_owned()),
                    WriteFileError::Open {
                        path: path.clone(),
                        cause,
                    },
                )
            })?;
            file.write_all(value.as_bytes()).map_err(|cause| {
                Error::with_cause(
                    WriteFailed(name.to_owned(), value.to_owned()),
                    WriteFileError::Write { path, cause },
                )
            })
        }

        fn get_max_value(&self, f: &str) -> Result<MaxValue> {
            self.open_path(f, false).and_then(|mut file| {
                let mut string = String::new();
                let res = file.read_to_string(&mut string);
                match res {
                    Ok(_) => parse_max_value(&string),
                    Err(e) => Err(Error::with_cause(ReadFailed(f.to_string()), e)),
                }
            })
        }

        #[doc(hidden)]
        fn path_exists(&self, p: &str) -> bool {
            std::path::Path::new(p).exists()
        }
    }

    pub(crate) trait CustomizedAttribute: ControllerInternal {
        fn set(&self, key: &str, value: &str) -> Result<()> {
            self.write_value(key, value)
        }

        /// Reject invalid names before any customized writes. I/O failures for
        /// valid names retain the released best-effort apply behavior.
        fn apply_attributes(&self, attrs: &HashMap<String, String>) -> Result<()> {
            for name in attrs.keys() {
                validate_attribute_name(name, "Controller::apply")?;
            }
            for (name, value) in attrs {
                let _ = self.set(name, value);
            }
            Ok(())
        }

        #[allow(dead_code)]
        fn get(&self, key: &str) -> Result<String> {
            self.open_path(key, false).and_then(|mut file: File| {
                let mut string = String::new();
                match file.read_to_string(&mut string) {
                    Ok(_) => Ok(string.trim().to_owned()),
                    Err(e) => Err(Error::with_cause(ReadFailed(key.to_string()), e)),
                }
            })
        }
    }
}

pub(crate) use crate::fs::sealed::{ControllerInternal, CustomizedAttribute};
use crate::CgroupPid;

/// Validate one Linux filename without normalizing away path components.
fn validate_attribute_name(name: &str, operation: &'static str) -> Result<()> {
    let cause = match name {
        "" => AttributeNameError::EmptyName {
            input: name.to_owned(),
            operation,
        },
        "." => AttributeNameError::CurrentComponent {
            input: name.to_owned(),
            operation,
        },
        ".." => AttributeNameError::ParentComponent {
            input: name.to_owned(),
            operation,
        },
        name if name.starts_with('/') => AttributeNameError::AbsolutePath {
            input: name.to_owned(),
            operation,
        },
        name if name.contains('/') => AttributeNameError::PathSeparator {
            input: name.to_owned(),
            operation,
        },
        name if name.contains('\0') => AttributeNameError::NulByte {
            input: name.to_owned(),
            operation,
        },
        _ => return Ok(()),
    };
    Err(Error::with_cause(InvalidPath, cause))
}

/// Read a kernel-version-dependent cgroup file.
///
/// A missing file means that the running kernel does not expose that optional
/// statistic. Any other failure must reach the caller.
pub(crate) fn optional_read<T: Default>(result: Result<T>) -> Result<T> {
    match result {
        Ok(value) => Ok(value),
        Err(error) if error.is_not_found() => Ok(T::default()),
        Err(error) => Err(error),
    }
}

/// A Controller is a subsystem attached to the control group.
///
/// Implementors are able to control certain aspects of a control group.
pub trait Controller {
    #[doc(hidden)]
    fn control_type(&self) -> Controllers;

    /// The file system path to the controller.
    fn path(&self) -> &Path;

    /// Root path of the file system to the controller.
    fn base(&self) -> &Path;

    /// Apply a set of resources to the Controller, invoking its internal functions to pass the
    /// kernel the information.
    ///
    /// Updates are not rolled back; earlier writes may have taken effect.
    fn apply(&self, res: &Resources) -> Result<()>;

    /// Create this controller
    fn create(&self) -> Result<()>;

    /// Does this controller already exist?
    fn exists(&self) -> bool;

    /// Set notify_on_release
    fn set_notify_on_release(&self, enable: bool) -> Result<()>;

    /// Set release_agent
    fn set_release_agent(&self, path: &str) -> Result<()>;

    /// Delete the controller.
    fn delete(&self) -> Result<()>;

    /// Attach a task to this controller.
    fn add_task(&self, pid: &CgroupPid) -> Result<()>;

    /// Attach a task to this controller.
    fn add_task_by_tgid(&self, pid: &CgroupPid) -> Result<()>;

    /// set cgroup type.
    fn set_cgroup_type(&self, cgroup_type: &str) -> Result<()>;

    /// get cgroup type.
    fn get_cgroup_type(&self) -> Result<String>;

    /// Get the list of tasks that this controller has, returning an error if reading fails.
    ///
    /// Built-in controllers read `tasks` on v1 and `cgroup.threads` on v2.
    /// Implementations must propagate I/O and parse failures instead of returning
    /// partial results or replacing malformed entries with PID zero.
    fn tasks(&self) -> Result<Vec<CgroupPid>>;

    /// Get the list of procs that this controller has, returning an error if reading fails.
    ///
    /// Built-in controllers read `cgroup.procs` on both versions.
    /// Implementations must propagate I/O and parse failures instead of returning
    /// partial results or replacing malformed entries with PID zero.
    fn procs(&self) -> Result<Vec<CgroupPid>>;

    fn v2(&self) -> bool;
}

impl<T> Controller for T
where
    T: ControllerInternal,
{
    fn control_type(&self) -> Controllers {
        ControllerInternal::control_type(self)
    }

    fn path(&self) -> &Path {
        self.get_path()
    }

    fn base(&self) -> &Path {
        self.get_base()
    }

    /// Apply a set of resources to the Controller, invoking its internal functions to pass the
    /// kernel the information.
    fn apply(&self, res: &Resources) -> Result<()> {
        ControllerInternal::apply(self, res)
    }

    /// Create this controller
    fn create(&self) -> Result<()> {
        std::fs::create_dir_all(self.get_path())
            .map_err(|err| Error::with_cause(ErrorKind::FsError, err))?;
        self.post_create();
        Ok(())
    }

    /// Set notify_on_release
    fn set_notify_on_release(&self, enable: bool) -> Result<()> {
        if self.is_v2() {
            return Err(Error::new(ErrorKind::CgroupVersion));
        }
        self.open_path("notify_on_release", true)
            .and_then(|mut file| {
                write!(file, "{}", enable as i32).map_err(|e| {
                    Error::with_cause(
                        ErrorKind::WriteFailed("notify_on_release".to_string(), enable.to_string()),
                        e,
                    )
                })
            })
    }

    /// Set release_agent
    fn set_release_agent(&self, path: &str) -> Result<()> {
        if self.is_v2() {
            return Err(Error::new(ErrorKind::CgroupVersion));
        }
        self.open_path("release_agent", true).and_then(|mut file| {
            file.write_all(path.as_bytes()).map_err(|e| {
                Error::with_cause(
                    ErrorKind::WriteFailed("release_agent".to_string(), path.to_string()),
                    e,
                )
            })
        })
    }
    /// Does this controller already exist?
    fn exists(&self) -> bool {
        self.get_path().exists()
    }

    /// Delete the controller.
    fn delete(&self) -> Result<()> {
        if !self.get_path().exists() {
            return Ok(());
        }

        // Compatible with runC for remove dir operation
        // https://github.com/opencontainers/runc/blob/main/libcontainer/cgroups/utils.go#L272
        //
        // We trying to remove all paths five times with increasing delay between tries.
        // If after all there are not removed cgroups - appropriate error will be
        // returned.
        let mut delay = std::time::Duration::from_millis(10);
        let cgroup_path = self.get_path();
        for _i in 0..4 {
            if let Ok(()) = remove_dir(cgroup_path) {
                return Ok(());
            }
            std::thread::sleep(delay);
            delay *= 2;
        }

        remove_dir(cgroup_path)
    }

    /// Attach a task to this controller.
    fn add_task(&self, pid: &CgroupPid) -> Result<()> {
        let mut file_name = "tasks";
        if self.is_v2() {
            file_name = "cgroup.threads";
        }
        self.open_path(file_name, true).and_then(|mut file| {
            file.write_all(pid.pid.to_string().as_ref()).map_err(|e| {
                Error::with_cause(
                    ErrorKind::WriteFailed(file_name.to_string(), pid.pid.to_string()),
                    e,
                )
            })
        })
    }

    /// Attach a task to this controller by thread group id.
    fn add_task_by_tgid(&self, pid: &CgroupPid) -> Result<()> {
        let file_name = "cgroup.procs";
        self.open_path(file_name, true).and_then(|mut file| {
            file.write_all(pid.pid.to_string().as_ref()).map_err(|e| {
                Error::with_cause(
                    ErrorKind::WriteFailed(file_name.to_string(), pid.pid.to_string()),
                    e,
                )
            })
        })
    }

    /// Get the list of procs that this controller has, returning an error if reading fails.
    fn procs(&self) -> Result<Vec<CgroupPid>> {
        let file_name = "cgroup.procs";
        let file = self.open_path(file_name, false)?;
        read_pids(BufReader::new(file), &self.get_path().join(file_name))
    }

    /// Get the list of tasks that this controller has, returning an error if reading fails.
    fn tasks(&self) -> Result<Vec<CgroupPid>> {
        let file_name = if self.is_v2() {
            "cgroup.threads"
        } else {
            "tasks"
        };
        let file = self.open_path(file_name, false)?;
        read_pids(BufReader::new(file), &self.get_path().join(file_name))
    }

    /// set cgroup.type
    fn set_cgroup_type(&self, cgroup_type: &str) -> Result<()> {
        if !self.is_v2() {
            return Err(Error::new(ErrorKind::CgroupVersion));
        }
        let file_name = "cgroup.type";
        self.open_path(file_name, true).and_then(|mut file| {
            file.write_all(cgroup_type.as_bytes()).map_err(|e| {
                Error::with_cause(
                    ErrorKind::WriteFailed(file_name.to_string(), cgroup_type.to_string()),
                    e,
                )
            })
        })
    }

    /// get cgroup.type
    fn get_cgroup_type(&self) -> Result<String> {
        if !self.is_v2() {
            return Err(Error::new(ErrorKind::CgroupVersion));
        }
        let file_name = "cgroup.type";
        self.open_path(file_name, false).and_then(|mut file: File| {
            let mut string = String::new();
            match file.read_to_string(&mut string) {
                Ok(_) => Ok(string.trim().to_owned()),
                Err(e) => Err(Error::with_cause(
                    ErrorKind::ReadFailed(file_name.to_string()),
                    e,
                )),
            }
        })
    }

    fn v2(&self) -> bool {
        self.is_v2()
    }
}

// remove_dir aims to remove cgroup path. It does so recursively,
// by removing any subdirectories (sub-cgroups) first.
fn remove_dir(dir: &Path) -> Result<()> {
    // try the fast path first.
    if fs::remove_dir(dir).is_ok() {
        return Ok(());
    }

    if dir.exists() && dir.is_dir() {
        for entry in fs::read_dir(dir)
            .map_err(|e| Error::with_cause(ReadFailed(dir.display().to_string()), e))?
        {
            let entry =
                entry.map_err(|e| Error::with_cause(ReadFailed(dir.display().to_string()), e))?;
            let path = entry.path();
            if path.is_dir() {
                remove_dir(&path)?;
            }
        }
        fs::remove_dir(dir).map_err(|e| Error::with_cause(RemoveFailed, e))?;
    }

    Ok(())
}

#[doc(hidden)]
pub trait ControllIdentifier {
    fn controller_type() -> Controllers;
}

/// A cgroup v1 or v2 hierarchy view shared by control group handles.
///
/// Implementations describe the hierarchy. Load root handles with
/// `Cgroup::load(hierarchy, CgroupPath::root())` and derive parent handles
/// with [`Cgroup::parent`].
pub trait Hierarchy: std::fmt::Debug + Send + Sync {
    /// Returns what subsystems are supported by the hierarchy.
    fn subsystems(&self) -> Vec<Subsystem>;

    /// Return the unified mount point on v2.
    ///
    /// Returns [`ErrorKind::CgroupVersion`] on v1, where controllers have
    /// separate mounts and no single root exists.
    ///
    /// Custom v1 implementations can construct the version error directly:
    ///
    /// ```
    /// use cgroups_rs::fs::error::{ErrorKind, Result};
    /// use cgroups_rs::fs::{Hierarchy, Subsystem};
    /// use std::path::PathBuf;
    ///
    /// #[derive(Debug)]
    /// struct LegacyHierarchy;
    /// impl Hierarchy for LegacyHierarchy {
    /// #   fn subsystems(&self) -> Vec<Subsystem> { Vec::new() }
    /// #   fn v2(&self) -> bool { false }
    ///     fn root(&self) -> Result<PathBuf> {
    ///         Err(ErrorKind::CgroupVersion.into())
    ///     }
    /// }
    /// # assert_eq!(LegacyHierarchy.root().unwrap_err().kind(), &ErrorKind::CgroupVersion);
    /// ```
    fn root(&self) -> Result<PathBuf>;

    fn v2(&self) -> bool;

    /// The immutable topology snapshot this hierarchy was constructed
    /// from, when the hierarchy is one of the discovery-built ones.
    ///
    /// Built-in hierarchies always expose their validated snapshot.
    /// Custom implementations may keep the default (`None`); a
    /// [`Cgroup`](crate::fs::Cgroup) still preserves the exact custom
    /// hierarchy when cloned because the trait object itself is shared.
    fn topology(&self) -> Option<std::sync::Arc<crate::core::discovery::CgroupTopology>> {
        None
    }
}

/// Resource limits for the memory subsystem.
#[derive(Debug, Clone, Eq, PartialEq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MemoryResources {
    /// How much memory (in bytes) can the kernel consume.
    pub kernel_memory_limit: Option<i64>,
    /// Upper limit of memory usage of the control group's tasks.
    pub memory_hard_limit: Option<i64>,
    /// How much memory the tasks in the control group can use when the system is under memory
    /// pressure.
    pub memory_soft_limit: Option<i64>,
    /// How much of the kernel's memory (in bytes) can be used for TCP-related buffers.
    pub kernel_tcp_memory_limit: Option<i64>,
    /// How much memory and swap together can the tasks in the control group use.
    pub memory_swap_limit: Option<i64>,
    /// Controls the tendency of the kernel to swap out parts of the address space of the tasks to
    /// disk. Lower value implies less likely.
    ///
    /// Note, however, that a value of zero does not mean the process is never swapped out. Use the
    /// traditional `mlock(2)` system call for that purpose.
    pub swappiness: Option<u64>,
    /// Customized key-value attributes.
    ///
    /// Keys must be single nonempty filenames, excluding `.`, `..`, `/`, and
    /// NUL bytes. Invalid keys make `Controller::apply()` return `InvalidPath`.
    ///
    /// # Usage:
    /// ```
    /// let resource = &mut cgroups_rs::fs::Resources::default();
    /// resource.memory.attrs.insert("memory.numa_balancing".to_string(), "true".to_string());
    /// // apply here
    /// ```
    pub attrs: HashMap<String, String>,
}

/// Resources limits on the number of processes.
#[derive(Debug, Clone, Eq, PartialEq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PidResources {
    /// The maximum number of processes that can exist in the control group.
    ///
    /// Note that attaching processes to the control group will still succeed _even_ if the limit
    /// would be violated, however forks/clones inside the control group will have with `EAGAIN` if
    /// they would violate the limit set here.
    pub maximum_number_of_processes: Option<MaxValue>,
}

/// Resources limits about how the tasks can use the CPU.
#[derive(Debug, Clone, Eq, PartialEq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CpuResources {
    // cpuset
    /// A comma-separated list of CPU IDs where the task in the control group can run. Dashes
    /// between numbers indicate ranges.
    pub cpus: Option<String>,
    /// Same syntax as the `cpus` field of this structure, but applies to memory nodes instead of
    /// processors.
    pub mems: Option<String>,
    // cpu
    /// Weight of how much of the total CPU time should this control group get. Note that this is
    /// hierarchical, so this is weighted against the siblings of this control group.
    pub shares: Option<u64>,
    /// In one `period`, how much can the tasks run in microseconds.
    pub quota: Option<i64>,
    /// Period of time in microseconds.
    pub period: Option<u64>,
    /// This is currently a no-operation.
    pub realtime_runtime: Option<i64>,
    /// This is currently a no-operation.
    pub realtime_period: Option<u64>,
    /// Customized key-value attributes.
    ///
    /// Keys follow the same filename rules as [`MemoryResources::attrs`].
    /// # Usage:
    /// ```
    /// let resource = &mut cgroups_rs::fs::Resources::default();
    /// resource.cpu.attrs.insert("cpu.cfs_init_buffer_us".to_string(), "10".to_string());
    /// // apply here
    /// ```
    pub attrs: HashMap<String, String>,
}

/// A device resource that can be allowed or denied access to.
#[derive(Debug, Clone, Eq, PartialEq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DeviceResource {
    /// If true, access to the device is allowed, otherwise it's denied.
    pub allow: bool,
    /// `'c'` for character device, `'b'` for block device; or `'a'` for all devices.
    pub devtype: crate::fs::devices::DeviceType,
    /// The major number of the device.
    pub major: i64,
    /// The minor number of the device.
    pub minor: i64,
    /// Sequence of `'r'`, `'w'` or `'m'`, each denoting read, write or mknod permissions.
    pub access: Vec<crate::fs::devices::DevicePermissions>,
}

/// Limit the usage of devices for the control group's tasks.
#[derive(Debug, Clone, Eq, PartialEq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DeviceResources {
    /// For each device in the list, the limits in the structure are applied.
    pub devices: Vec<DeviceResource>,
}

/// Assigned priority for a network device.
#[derive(Debug, Clone, Eq, PartialEq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NetworkPriority {
    /// The name (as visible in `ifconfig`) of the interface.
    pub name: String,
    /// Assigned priority.
    pub priority: u64,
}

/// Collections of limits and tags that can be imposed on packets emitted by the tasks in the
/// control group.
#[derive(Debug, Clone, Eq, PartialEq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NetworkResources {
    /// The networking class identifier to attach to the packets.
    ///
    /// This can then later be used in iptables and such to have special rules.
    pub class_id: Option<u64>,
    /// Priority of the egress traffic for each interface.
    pub priorities: Vec<NetworkPriority>,
}

/// A hugepage type and its consumption limit for the control group.
#[derive(Debug, Clone, Eq, PartialEq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HugePageResource {
    /// The size of the hugepage, i.e. `2MB`, `1GB`, etc.
    pub size: String,
    /// The amount of bytes (of memory consumed by the tasks) that are allowed to be backed by
    /// hugepages.
    pub limit: u64,
}

/// Provides the ability to set consumption limit on each type of hugepages.
#[derive(Debug, Clone, Eq, PartialEq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HugePageResources {
    /// Set a limit of consumption for each hugepages type.
    pub limits: Vec<HugePageResource>,
}

/// Weight for a particular block device.
#[derive(Debug, Clone, Eq, PartialEq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BlkIoDeviceResource {
    /// The major number of the device.
    pub major: u64,
    /// The minor number of the device.
    pub minor: u64,
    /// The weight of the device against the descendant nodes.
    pub weight: Option<u16>,
    /// The weight of the device against the sibling nodes.
    pub leaf_weight: Option<u16>,
}

/// Provides the ability to throttle a device (both byte/sec, and IO op/s)
#[derive(Debug, Clone, Eq, PartialEq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BlkIoDeviceThrottleResource {
    /// The major number of the device.
    pub major: u64,
    /// The minor number of the device.
    pub minor: u64,
    /// The rate.
    pub rate: u64,
}

/// General block I/O resource limits.
#[derive(Debug, Clone, Eq, PartialEq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BlkIoResources {
    /// The weight of the control group against descendant nodes.
    pub weight: Option<u16>,
    /// The weight of the control group against sibling nodes.
    pub leaf_weight: Option<u16>,
    /// For each device, a separate weight (both normal and leaf) can be provided.
    pub weight_device: Vec<BlkIoDeviceResource>,
    /// Throttled read bytes/second can be provided for each device.
    pub throttle_read_bps_device: Vec<BlkIoDeviceThrottleResource>,
    /// Throttled read IO operations per second can be provided for each device.
    pub throttle_read_iops_device: Vec<BlkIoDeviceThrottleResource>,
    /// Throttled written bytes/second can be provided for each device.
    pub throttle_write_bps_device: Vec<BlkIoDeviceThrottleResource>,
    /// Throttled write IO operations per second can be provided for each device.
    pub throttle_write_iops_device: Vec<BlkIoDeviceThrottleResource>,

    /// Customized key-value attributes.
    ///
    /// Keys follow the same filename rules as [`MemoryResources::attrs`].
    /// # Usage:
    /// ```
    /// let resource = &mut cgroups_rs::fs::Resources::default();
    /// resource.blkio.attrs.insert("io.cost.weight".to_string(), "10".to_string());
    /// // apply here
    /// ```
    pub attrs: HashMap<String, String>,
}

/// The resource limits and constraints that will be set on the control group.
#[derive(Debug, Clone, Eq, PartialEq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Resources {
    /// Memory usage related limits.
    pub memory: MemoryResources,
    /// Process identifier related limits.
    pub pid: PidResources,
    /// CPU related limits.
    pub cpu: CpuResources,
    /// Device related limits.
    pub devices: DeviceResources,
    /// Network related tags and limits.
    pub network: NetworkResources,
    /// Hugepages consumption related limits.
    pub hugepages: HugePageResources,
    /// Block device I/O related limits.
    pub blkio: BlkIoResources,
}

impl Subsystem {
    fn enter(self, path: &Path) -> Self {
        match self {
            Subsystem::Pid(mut cont) => Subsystem::Pid({
                cont.get_path_mut().push(path);
                cont
            }),
            Subsystem::Mem(mut cont) => Subsystem::Mem({
                cont.get_path_mut().push(path);
                cont
            }),
            Subsystem::CpuSet(mut cont) => Subsystem::CpuSet({
                cont.get_path_mut().push(path);
                cont
            }),
            Subsystem::CpuAcct(mut cont) => Subsystem::CpuAcct({
                cont.get_path_mut().push(path);
                cont
            }),
            Subsystem::Cpu(mut cont) => Subsystem::Cpu({
                cont.get_path_mut().push(path);
                cont
            }),
            Subsystem::Devices(mut cont) => Subsystem::Devices({
                cont.get_path_mut().push(path);
                cont
            }),
            Subsystem::Freezer(mut cont) => Subsystem::Freezer({
                cont.get_path_mut().push(path);
                cont
            }),
            Subsystem::NetCls(mut cont) => Subsystem::NetCls({
                cont.get_path_mut().push(path);
                cont
            }),
            Subsystem::BlkIo(mut cont) => Subsystem::BlkIo({
                cont.get_path_mut().push(path);
                cont
            }),
            Subsystem::PerfEvent(mut cont) => Subsystem::PerfEvent({
                cont.get_path_mut().push(path);
                cont
            }),
            Subsystem::NetPrio(mut cont) => Subsystem::NetPrio({
                cont.get_path_mut().push(path);
                cont
            }),
            Subsystem::HugeTlb(mut cont) => Subsystem::HugeTlb({
                cont.get_path_mut().push(path);
                cont
            }),
            Subsystem::Rdma(mut cont) => Subsystem::Rdma({
                cont.get_path_mut().push(path);
                cont
            }),
            Subsystem::Systemd(mut cont) => Subsystem::Systemd({
                cont.get_path_mut().push(path);
                cont
            }),
        }
    }

    pub fn to_controller(&self) -> &dyn Controller {
        match self {
            Subsystem::Pid(cont) => cont,
            Subsystem::Mem(cont) => cont,
            Subsystem::CpuSet(cont) => cont,
            Subsystem::CpuAcct(cont) => cont,
            Subsystem::Cpu(cont) => cont,
            Subsystem::Devices(cont) => cont,
            Subsystem::Freezer(cont) => cont,
            Subsystem::NetCls(cont) => cont,
            Subsystem::BlkIo(cont) => cont,
            Subsystem::PerfEvent(cont) => cont,
            Subsystem::NetPrio(cont) => cont,
            Subsystem::HugeTlb(cont) => cont,
            Subsystem::Rdma(cont) => cont,
            Subsystem::Systemd(cont) => cont,
        }
    }

    pub fn controller_name(&self) -> String {
        self.to_controller().control_type().to_string()
    }
}

/// The values for `memory.hight` or `pids.max`
#[derive(Eq, PartialEq, Copy, Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum MaxValue {
    /// This value is returned when the text is `"max"`.
    Max,
    /// When the value is a numerical value, they are returned via this enum field.
    Value(i64),
}

#[allow(clippy::derivable_impls)]
impl Default for MaxValue {
    fn default() -> Self {
        MaxValue::Max
    }
}

impl MaxValue {
    #[allow(clippy::should_implement_trait, clippy::wrong_self_convention)]
    fn to_i64(&self) -> i64 {
        match self {
            MaxValue::Max => -1,
            MaxValue::Value(num) => *num,
        }
    }
}

impl fmt::Display for MaxValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MaxValue::Max => write!(f, "max"),
            MaxValue::Value(num) => write!(f, "{}", num),
        }
    }
}

pub fn parse_max_value(s: &str) -> Result<MaxValue> {
    if s.trim() == "max" {
        return Ok(MaxValue::Max);
    }
    match s.trim().parse() {
        Ok(val) => Ok(MaxValue::Value(val)),
        Err(e) => Err(Error::with_cause(ParseError, e)),
    }
}

// Flat keyed
//  KEY0 VAL0\n
//  KEY1 VAL1\n
pub fn flat_keyed_to_vec(mut file: File) -> Result<Vec<(String, i64)>> {
    let mut content = String::new();
    file.read_to_string(&mut content)
        .map_err(|e| Error::with_cause(ReadFailed("FIXME: read_string_from".to_string()), e))?;

    let mut v = Vec::new();
    for line in content.lines() {
        let parts: Vec<&str> = line.split(' ').collect();
        if parts.len() == 2 {
            if let Ok(i) = parts[1].parse::<i64>() {
                v.push((parts[0].to_string(), i));
            }
        }
    }
    Ok(v)
}

// Flat keyed
//  KEY0 VAL0\n
//  KEY1 VAL1\n
pub fn flat_keyed_to_hashmap(mut file: File) -> Result<HashMap<String, i64>> {
    let mut content = String::new();
    file.read_to_string(&mut content)
        .map_err(|e| Error::with_cause(ReadFailed("FIXME: read_string_from".to_string()), e))?;

    let mut h = HashMap::new();
    for line in content.lines() {
        let parts: Vec<&str> = line.split(' ').collect();
        if parts.len() == 2 {
            if let Ok(i) = parts[1].parse::<i64>() {
                h.insert(parts[0].to_string(), i);
            }
        }
    }
    Ok(h)
}

// Nested keyed
//  KEY0 SUB_KEY0=VAL00 SUB_KEY1=VAL01...
//  KEY1 SUB_KEY0=VAL10 SUB_KEY1=VAL11...
pub fn nested_keyed_to_hashmap(mut file: File) -> Result<HashMap<String, HashMap<String, i64>>> {
    let mut content = String::new();
    file.read_to_string(&mut content)
        .map_err(|e| Error::with_cause(ReadFailed("FIXME: read_string_from".to_string()), e))?;

    let mut h = HashMap::new();
    for line in content.lines() {
        let parts: Vec<&str> = line.split(' ').collect();
        if parts.is_empty() {
            continue;
        }
        let mut th = HashMap::new();
        for item in parts[1..].iter() {
            let fields: Vec<&str> = item.split('=').collect();
            if fields.len() == 2 {
                if let Ok(i) = fields[1].parse::<i64>() {
                    th.insert(fields[0].to_string(), i);
                }
            }
        }
        h.insert(parts[0].to_string(), th);
    }

    Ok(h)
}

fn parse_pid(input: &str, line: usize) -> std::result::Result<CgroupPid, error::ParsePidError> {
    input
        .trim()
        .parse::<u64>()
        .map(CgroupPid::from)
        .map_err(|cause| error::ParsePidError {
            line,
            input: input.to_owned(),
            cause,
        })
}

fn read_pids(reader: impl BufRead, path: &Path) -> Result<Vec<CgroupPid>> {
    let mut pids = Vec::new();
    for (index, line) in reader.lines().enumerate() {
        let input =
            line.map_err(|cause| Error::with_cause(ReadFailed(path.display().to_string()), cause))?;
        if input.trim().is_empty() {
            continue;
        }
        let pid = parse_pid(&input, index + 1).map_err(|cause| {
            Error::with_cause(
                ParseError,
                error::ParsePidFileError {
                    path: path.to_path_buf(),
                    cause,
                },
            )
        })?;
        pids.push(pid);
    }
    Ok(pids)
}

fn read_from<T>(mut file: File) -> Result<T>
where
    T: FromStr,
    <T as FromStr>::Err: 'static + Send + Sync + std::error::Error,
{
    let mut string = String::new();
    match file.read_to_string(&mut string) {
        Ok(_) => string
            .trim()
            .parse::<T>()
            .map_err(|e| Error::with_cause(ParseError, e)),
        Err(e) => Err(Error::with_cause(
            ReadFailed("FIXME: can't get path in fn read_from".to_string()),
            e,
        )),
    }
}

fn read_string_from(mut file: File) -> Result<String> {
    let mut string = String::new();
    match file.read_to_string(&mut string) {
        Ok(_) => Ok(string.trim().to_string()),
        Err(e) => Err(Error::with_cause(
            ReadFailed("FIXME: can't get path in fn read_string_from".to_string()),
            e,
        )),
    }
}

/// read and parse an u64 data
fn read_u64_from(file: File) -> Result<u64> {
    read_from::<u64>(file)
}

/// read and parse an i64 data
fn read_i64_from(file: File) -> Result<i64> {
    read_from::<i64>(file)
}

#[cfg(test)]
mod controller_attribute_tests {
    use super::*;
    use crate::tests::TestDir;
    use std::error::Error as _;
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    fn assert_name_error(error: &Error, name: &str, operation: &str) {
        assert_eq!(error.kind(), &InvalidPath);
        let context = error
            .source()
            .unwrap()
            .downcast_ref::<AttributeNameError>()
            .unwrap();
        let (input, actual_operation) = match context {
            AttributeNameError::EmptyName { input, operation }
            | AttributeNameError::AbsolutePath { input, operation }
            | AttributeNameError::CurrentComponent { input, operation }
            | AttributeNameError::ParentComponent { input, operation }
            | AttributeNameError::PathSeparator { input, operation }
            | AttributeNameError::NulByte { input, operation } => (input, operation),
        };
        assert_eq!(input, name);
        assert_eq!(*actual_operation, operation);
    }

    #[test]
    fn attribute_writes_reject_paths_before_opening_targets() {
        let fixture = TestDir::new("attribute_paths");
        let directory = fixture.join(OsStr::from_bytes(b"group-\xff"));
        fs::create_dir(&directory).unwrap();
        let controller = MemController::new(directory.clone(), directory.clone(), false);
        let outside = fixture.join("outside");
        fs::write(&outside, "unchanged").unwrap();
        let absolute = outside.to_str().unwrap();

        for name in [
            absolute,
            "../outside",
            "../created",
            "child/limit",
            "./memory.limit_in_bytes",
            "memory.limit_in_bytes/",
            "",
            ".",
            "..",
            "memory.\0limit",
        ] {
            let error = controller.write_value(name, "overwrite").unwrap_err();
            assert_name_error(&error, name, "ControllerInternal::write_value");
            assert_eq!(fs::read_to_string(&outside).unwrap(), "unchanged");
            assert!(!fixture.join("created").exists());
            assert_eq!(fs::read_dir(&directory).unwrap().count(), 0);
        }
    }

    #[test]
    fn customized_attributes_reject_paths_before_any_attribute_write() {
        for v2 in [false, true] {
            let fixture = TestDir::new("attribute_apply_paths");
            let directory = fixture.join("group");
            fs::create_dir(&directory).unwrap();
            let outside = fixture.join("outside");
            fs::write(&outside, "unchanged").unwrap();
            let memory = MemController::new(directory.clone(), directory.clone(), v2);
            let cpu = CpuController::new(directory.clone(), directory.clone(), v2);
            let blkio = BlkIoController::new(directory.clone(), directory.clone(), v2);

            for invalid in [outside.to_str().unwrap(), "../outside", "../created"] {
                let mut resources = Resources::default();
                for attrs in [
                    &mut resources.memory.attrs,
                    &mut resources.cpu.attrs,
                    &mut resources.blkio.attrs,
                ] {
                    attrs.insert("vendor.limit".into(), "updated".into());
                    attrs.insert(invalid.into(), "overwrite".into());
                }

                for controller in [&memory as &dyn Controller, &cpu, &blkio] {
                    fs::write(directory.join("vendor.limit"), "unchanged").unwrap();
                    let error = controller.apply(&resources).unwrap_err();
                    assert_name_error(&error, invalid, "Controller::apply");
                    assert_eq!(fs::read_to_string(&outside).unwrap(), "unchanged");
                    assert!(!fixture.join("created").exists());
                    assert_eq!(
                        fs::read_to_string(directory.join("vendor.limit")).unwrap(),
                        "unchanged"
                    );
                }
            }
        }
    }

    #[test]
    fn customized_attributes_keep_valid_names_and_best_effort_io() {
        for v2 in [false, true] {
            let fixture = TestDir::new("attribute_apply_valid");
            let directory = fixture.path().to_path_buf();
            let memory = MemController::new(directory.clone(), directory.clone(), v2);
            let cpu = CpuController::new(directory.clone(), directory.clone(), v2);
            let blkio = BlkIoController::new(directory.clone(), directory.clone(), v2);
            let mut resources = Resources::default();
            for attrs in [
                &mut resources.memory.attrs,
                &mut resources.cpu.attrs,
                &mut resources.blkio.attrs,
            ] {
                attrs.insert("vendor.limit".into(), "updated".into());
                attrs.insert("vendor..limit".into(), "accepted".into());
            }
            for controller in [&memory as &dyn Controller, &cpu, &blkio] {
                fs::write(directory.join("vendor.limit"), "unchanged").unwrap();
                controller.apply(&resources).unwrap();
                assert_eq!(
                    fs::read_to_string(directory.join("vendor.limit")).unwrap(),
                    "updated"
                );
                assert_eq!(
                    fs::read_to_string(directory.join("vendor..limit")).unwrap(),
                    "accepted"
                );
            }

            // An ordinary directory produces a root-independent open failure.
            fs::remove_file(directory.join("vendor.limit")).unwrap();
            fs::create_dir(directory.join("vendor.limit")).unwrap();
            for controller in [&memory as &dyn Controller, &cpu, &blkio] {
                controller.apply(&resources).unwrap();
            }
            let error = memory.set("vendor.limit", "updated").unwrap_err();
            assert_eq!(
                error.kind(),
                &WriteFailed("vendor.limit".into(), "updated".into())
            );
            assert!(matches!(
                error.source().unwrap().downcast_ref::<WriteFileError>().unwrap(),
                WriteFileError::Open { path, cause }
                    if path == &directory.join("vendor.limit")
                        && cause.raw_os_error() == Some(libc::EISDIR)
            ));
        }
    }
}

#[cfg(test)]
mod controller_membership_tests {
    use super::*;

    #[test]
    fn membership_read_failure_preserves_full_path_and_errno_after_valid_prefix() {
        use std::error::Error as _;
        use std::io::{self, Cursor};

        struct FailingRead;
        impl Read for FailingRead {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::from_raw_os_error(libc::EIO))
            }
        }

        let path = Path::new("/fixture/cgroup/cgroup.procs");
        let reader = BufReader::new(Cursor::new(b"100\n").chain(FailingRead));
        let error = read_pids(reader, path).unwrap_err();
        assert_eq!(error.kind(), &ReadFailed(path.display().to_string()));
        assert_eq!(
            error
                .source()
                .unwrap()
                .downcast_ref::<io::Error>()
                .unwrap()
                .raw_os_error(),
            Some(libc::EIO)
        );
    }

    /// Models a downstream implementation of the fallible membership contract.
    struct CustomController {
        path: PathBuf,
    }

    impl Controller for CustomController {
        fn control_type(&self) -> Controllers {
            Controllers::Cpu
        }

        fn path(&self) -> &Path {
            &self.path
        }

        fn base(&self) -> &Path {
            &self.path
        }

        fn apply(&self, _res: &Resources) -> Result<()> {
            Ok(())
        }

        fn create(&self) -> Result<()> {
            Ok(())
        }

        fn exists(&self) -> bool {
            true
        }

        fn set_notify_on_release(&self, _enable: bool) -> Result<()> {
            Ok(())
        }

        fn set_release_agent(&self, _path: &str) -> Result<()> {
            Ok(())
        }

        fn delete(&self) -> Result<()> {
            Ok(())
        }

        fn add_task(&self, _pid: &CgroupPid) -> Result<()> {
            Ok(())
        }

        fn add_task_by_tgid(&self, _pid: &CgroupPid) -> Result<()> {
            Ok(())
        }

        fn set_cgroup_type(&self, _cgroup_type: &str) -> Result<()> {
            Ok(())
        }

        fn get_cgroup_type(&self) -> Result<String> {
            Ok(String::new())
        }

        fn tasks(&self) -> Result<Vec<CgroupPid>> {
            Ok(vec![CgroupPid::from(11u64)])
        }

        fn procs(&self) -> Result<Vec<CgroupPid>> {
            Err(Error::with_cause(
                ReadFailed(self.path.join("cgroup.procs").display().to_string()),
                std::io::Error::from_raw_os_error(libc::EACCES),
            ))
        }

        fn v2(&self) -> bool {
            false
        }
    }

    #[test]
    fn custom_controller_membership_methods_return_values_and_errors() {
        use std::error::Error as _;

        let custom = CustomController {
            path: PathBuf::from("/unused"),
        };
        let controller: &dyn Controller = &custom;

        assert_eq!(controller.tasks().unwrap(), [CgroupPid::from(11u64)]);
        let error = controller.procs().unwrap_err();
        assert_eq!(
            error.kind(),
            &ReadFailed("/unused/cgroup.procs".to_string())
        );
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
