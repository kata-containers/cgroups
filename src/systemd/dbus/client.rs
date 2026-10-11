// Copyright 2021-2023 Kata Contributors
// Copyright (c) 2025 Ant Group
//
// SPDX-License-Identifier: Apache-2.0 or MIT
//

use std::convert::TryFrom;
use std::future::Future;
use std::time::Duration;

use async_io::Timer;
use futures_lite::{future, StreamExt};
use zbus::zvariant::Value;
use zbus::{Error as ZbusError, Result as ZbusResult};

use crate::model::ProcessId;
use crate::systemd::dbus::error::{Error, Result};
use crate::systemd::dbus::proxy::systemd_manager_proxy;
use crate::systemd::dbus::systemd_manager_proxy::ManagerProxy as AsyncSystemManager;
#[cfg(any(feature = "oci", test))]
use crate::systemd::dbus::systemd_manager_proxy::ManagerProxyBlocking;
use crate::systemd::{Property, NO_SUCH_UNIT, PIDS, UNIT_MODE_REPLACE};
use crate::CgroupPid;

const START_JOB_TIMEOUT: Duration = Duration::from_secs(30);

pub struct SystemdClient<'a> {
    /// The name of the systemd unit (slice or scope)
    unit: String,
    props: Vec<Property<'a>>,
}

impl<'a> SystemdClient<'a> {
    pub fn new(unit: &str, props: Vec<Property<'a>>) -> Result<Self> {
        Ok(Self {
            unit: unit.to_string(),
            props,
        })
    }
}

impl SystemdClient<'_> {
    /// Set the pid to the PIDs property of the unit.
    ///
    /// Append a process ID to the PIDs property of the unit. If not
    /// exists, one property will be created.
    pub fn set_pid_prop(&mut self, pid: CgroupPid) -> Result<()> {
        let pid = ProcessId::try_from(pid)?;
        if self.try_exists()? {
            return Ok(());
        }

        for prop in self.props.iter_mut() {
            if prop.0 == PIDS {
                // If PIDS is already set, we append the new pid to the existing list.
                if let Value::Array(arr) = &mut prop.1 {
                    arr.append(pid.get().into())
                        .map_err(|_| Error::InvalidProperties)?;
                    return Ok(());
                }
                // Invalid type of PIDs
                return Err(Error::InvalidProperties);
            }
        }
        // If PIDS is not set, we create a new property.
        self.props
            .push((PIDS, Value::Array(vec![pid.get()].into())));
        Ok(())
    }

    /// Start a slice or a scope unit controlled and supervised by systemd.
    ///
    /// For more information, see:
    /// https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html
    /// https://www.freedesktop.org/software/systemd/man/latest/systemd.slice.html
    /// https://www.freedesktop.org/software/systemd/man/latest/systemd.scope.html
    pub fn start(&self) -> Result<()> {
        // PIDs property must be present
        if !self.props.iter().any(|(k, _)| k == &PIDS) {
            return Err(Error::InvalidProperties);
        }

        let props_borrowed: Vec<(&str, &zbus::zvariant::Value)> =
            self.props.iter().map(|(k, v)| (*k, v)).collect();
        let props_borrowed: Vec<&(&str, &Value)> = props_borrowed.iter().collect();

        async_io::block_on(async {
            let connection = zbus::Connection::system().await?;
            let sys_proxy = AsyncSystemManager::new(&connection).await?;

            // StartTransientUnit only queues the start job. Install the signal
            // listener first so a fast job cannot finish before we start waiting.
            let mut job_removed = sys_proxy
                .receive_job_removed_with_args(&[(2, self.unit.as_str())])
                .await?;
            sys_proxy.subscribe().await?;

            let job = sys_proxy
                .start_transient_unit(&self.unit, UNIT_MODE_REPLACE, &props_borrowed, &[])
                .await?;
            let job_path = job.as_str().to_string();
            let expected_job_path = job_path.clone();

            let wait_for_job = async move {
                while let Some(signal) = job_removed.next().await {
                    let args = signal.args()?;
                    if args.job.as_str() != expected_job_path.as_str() {
                        continue;
                    }

                    return match args.result {
                        "done" => Ok(()),
                        result => Err(Error::JobFailed(result.to_string())),
                    };
                }

                Err(Error::JobRemovedSignalStreamClosed)
            };
            let timeout_error = Error::JobWaitTimedOut {
                unit: self.unit.clone(),
                job: job_path,
                timeout: START_JOB_TIMEOUT,
            };

            with_timeout(wait_for_job, START_JOB_TIMEOUT, timeout_error).await
        })
    }

    /// Stop the current transient unit, the processes will be killed on
    /// unit stop, see [1].
    ///
    /// 1. https://www.freedesktop.org/software/systemd/man/latest/systemd.kill.html#KillMode=
    pub fn stop(&self) -> Result<()> {
        let sys_proxy = systemd_manager_proxy()?;

        let ret = sys_proxy.stop_unit(&self.unit, UNIT_MODE_REPLACE);
        ignore_no_such_unit(ret)?;

        // If we stop the unit and it still exists, it may be in a failed
        // state, so we will try to reset it.
        if self.exists() {
            let ret = sys_proxy.reset_failed_unit(&self.unit);
            ignore_no_such_unit(ret)?;
        }

        Ok(())
    }

    /// Set properties for the unit through dbus `SetUnitProperties`.
    pub fn set_properties(&mut self, properties: &[Property<'static>]) -> Result<()> {
        for prop in properties {
            let new = prop.1.try_clone().map_err(|_| Error::InvalidProperties)?;
            // Try to update the value first, if fails, append it.
            if let Some(existing) = self.props.iter_mut().find(|p| p.0 == prop.0) {
                existing.1 = new;
            } else {
                self.props.push((prop.0, new));
            }
        }

        // The unit must exist before setting properties.
        if !self.exists() {
            return Ok(());
        }

        let sys_proxy = systemd_manager_proxy()?;

        let props_borrowed: Vec<(&str, &Value)> = properties.iter().map(|(k, v)| (*k, v)).collect();
        let props_borrowed: Vec<&(&str, &Value)> = props_borrowed.iter().collect();

        sys_proxy.set_unit_properties(&self.unit, true, &props_borrowed)?;

        Ok(())
    }

    /// Freeze the unit through dbus `FreezeUnit`.
    pub fn freeze(&self) -> Result<()> {
        let sys_proxy = systemd_manager_proxy()?;

        sys_proxy.freeze_unit(&self.unit)?;

        Ok(())
    }

    /// Thaw the frozen unit through dbus `ThawUnit`.
    pub fn thaw(&self) -> Result<()> {
        let sys_proxy = systemd_manager_proxy()?;

        sys_proxy.thaw_unit(&self.unit)?;

        Ok(())
    }

    /// Check if the unit exists through dbus `GetUnit`.
    ///
    /// Returns `Ok(true)` if the unit exists, `Ok(false)` if systemd returns
    /// `org.freedesktop.systemd1.NoSuchUnit`, or an `Err` if D-Bus communication
    /// or authorization fails.
    pub fn try_exists(&self) -> Result<bool> {
        let sys_proxy = systemd_manager_proxy()?;
        match sys_proxy.get_unit(&self.unit) {
            Ok(_) => Ok(true),
            Err(ZbusError::MethodError(err_name, _, _)) if err_name.as_str() == NO_SUCH_UNIT => {
                Ok(false)
            }
            Err(e) => Err(Error::Dbus(e)),
        }
    }

    /// Read the existing scope's actual delegation setting. Unit names and
    /// requested transient properties do not establish ownership of its tree.
    #[cfg(feature = "oci")]
    pub(crate) fn try_delegated(&self) -> Result<bool> {
        let manager = systemd_manager_proxy()?;
        self.delegated_with_proxy(&manager)
    }

    /// Controllers requested for delegation. This list still needs to be
    /// intersected with the visible, realized hierarchies of the active dialect.
    #[cfg(feature = "oci")]
    pub(crate) fn try_delegated_controllers(&self) -> Result<Vec<String>> {
        let manager = systemd_manager_proxy()?;
        self.delegated_controllers_with_proxy(&manager)
    }

    #[cfg(any(feature = "oci", test))]
    fn scope_with_proxy<'a>(
        &self,
        manager: &ManagerProxyBlocking<'a>,
    ) -> Result<zbus::blocking::Proxy<'a>> {
        let path = manager.get_unit(&self.unit)?;
        Ok(zbus::blocking::Proxy::new(
            manager.inner().connection(),
            "org.freedesktop.systemd1",
            path,
            "org.freedesktop.systemd1.Scope",
        )?)
    }

    #[cfg(any(feature = "oci", test))]
    fn delegated_with_proxy(&self, manager: &ManagerProxyBlocking<'_>) -> Result<bool> {
        Ok(self
            .scope_with_proxy(manager)?
            .get_property::<bool>("Delegate")?)
    }

    #[cfg(any(feature = "oci", test))]
    fn delegated_controllers_with_proxy(
        &self,
        manager: &ManagerProxyBlocking<'_>,
    ) -> Result<Vec<String>> {
        Ok(self
            .scope_with_proxy(manager)?
            .get_property("DelegateControllers")?)
    }

    /// Check if the unit exists.
    ///
    /// For backwards compatibility, errors are swallowed and return `false`.
    /// Callers on fallible attachment paths should prefer [`SystemdClient::try_exists`].
    pub fn exists(&self) -> bool {
        self.try_exists().unwrap_or(false)
    }

    /// Add a process (tgid) to the unit through dbus
    /// `AttachProcessesToUnit`.
    pub fn add_process(&self, pid: CgroupPid, subcgroup: &str) -> Result<()> {
        let pid = ProcessId::try_from(pid)?;
        self.add_process_id(pid, subcgroup)
    }

    /// Add a validated [`ProcessId`] (tgid) to the unit through dbus
    /// `AttachProcessesToUnit`.
    pub fn add_process_id(&self, pid: ProcessId, subcgroup: &str) -> Result<()> {
        let sys_proxy = systemd_manager_proxy()?;

        sys_proxy.attach_processes_to_unit(&self.unit, subcgroup, &[pid.get()])?;

        Ok(())
    }
}

async fn with_timeout<T, F>(operation: F, timeout: Duration, timeout_error: Error) -> Result<T>
where
    F: Future<Output = Result<T>>,
{
    future::race(operation, async move {
        Timer::after(timeout).await;
        Err(timeout_error)
    })
    .await
}

fn ignore_no_such_unit<T>(result: ZbusResult<T>) -> ZbusResult<bool> {
    if let Err(ZbusError::MethodError(err_name, _, _)) = &result {
        if err_name.as_str() == NO_SUCH_UNIT {
            return Ok(true);
        }
    }
    result.map(|_| false)
}

#[cfg(test)]
pub mod tests {
    //! Unit tests for the SystemdClient
    //!
    //! Not sure why the tests are going to fail if we run them in
    //! parallel. Everything goes smoothly in serial.
    //!
    //! $ cargo test --package cgroups-rs --lib \
    //!   -- systemd::dbus::client::tests \
    //!   --show-output --test-threads=1

    use std::fs;
    use std::path::Path;
    use std::process::Command;
    use std::thread::sleep;
    use std::time::Duration;

    use rand::distributions::Alphanumeric;
    use rand::Rng;

    use crate::fs::hierarchies;
    use crate::skip_if_not_root;
    use crate::systemd::dbus::client::*;
    use crate::systemd::dbus::error::Error;
    use crate::systemd::props::PropertiesBuilder;
    use crate::systemd::utils::expand_slice;
    use crate::systemd::{DEFAULT_DESCRIPTION, DESCRIPTION, PIDS};
    use crate::tests::{spawn_sleep_inf, spawn_yes};

    const TEST_SLICE: &str = "cgroupsrs-test.slice";

    #[test]
    // Keep compatibility with zbus 5.8, before async_io_unix_stream was added.
    #[allow(deprecated)]
    fn test_actual_delegation_property_and_errors_on_private_bus() {
        use std::sync::atomic::{AtomicU8, Ordering};
        use std::sync::Arc;

        struct MockManager;
        #[zbus::interface(name = "org.freedesktop.systemd1.Manager")]
        impl MockManager {
            fn get_unit(&self, _unit: &str) -> zbus::zvariant::ObjectPath<'static> {
                zbus::zvariant::ObjectPath::try_from("/org/freedesktop/systemd1/unit/test").unwrap()
            }
        }

        struct MockScope(Arc<AtomicU8>);
        #[zbus::interface(name = "org.freedesktop.systemd1.Scope")]
        impl MockScope {
            #[zbus(property)]
            fn delegate(&self) -> zbus::fdo::Result<bool> {
                match self.0.load(Ordering::SeqCst) {
                    0 => Ok(false),
                    1 => Ok(true),
                    _ => Err(zbus::fdo::Error::AccessDenied(
                        "fixture denies Delegate".to_string(),
                    )),
                }
            }

            #[zbus(property)]
            fn delegate_controllers(&self) -> zbus::fdo::Result<Vec<String>> {
                match self.0.load(Ordering::SeqCst) {
                    0 => Ok(Vec::new()),
                    1 => Ok(vec!["cpu".to_string(), "memory".to_string()]),
                    _ => Err(zbus::fdo::Error::AccessDenied(
                        "fixture denies DelegateControllers".to_string(),
                    )),
                }
            }
        }

        // Both ends are synthetic peers over an in-process socket pair. No
        // system bus connection, unit creation, or host cgroup access occurs.
        let state = Arc::new(AtomicU8::new(0));
        let (server_socket, client_socket) = std::os::unix::net::UnixStream::pair().unwrap();
        let server = zbus::connection::Builder::unix_stream(server_socket)
            .server(zbus::Guid::generate())
            .unwrap()
            .p2p()
            .serve_at("/org/freedesktop/systemd1", MockManager)
            .unwrap()
            .serve_at(
                "/org/freedesktop/systemd1/unit/test",
                MockScope(state.clone()),
            )
            .unwrap();
        let client = zbus::connection::Builder::unix_stream(client_socket).p2p();
        let (server, connection) =
            async_io::block_on(futures_lite::future::zip(server.build(), client.build()));
        let _server = server.unwrap();
        let connection = zbus::blocking::Connection::from(connection.unwrap());
        let manager = ManagerProxyBlocking::new(&connection).unwrap();
        let client = SystemdClient::new("test.scope", Vec::new()).unwrap();
        assert!(!client.delegated_with_proxy(&manager).unwrap());
        assert!(client
            .delegated_controllers_with_proxy(&manager)
            .unwrap()
            .is_empty());
        state.store(1, Ordering::SeqCst);
        assert!(client.delegated_with_proxy(&manager).unwrap());
        assert_eq!(
            client.delegated_controllers_with_proxy(&manager).unwrap(),
            ["cpu", "memory"]
        );
        state.store(2, Ordering::SeqCst);
        assert!(matches!(
            client.delegated_with_proxy(&manager),
            Err(Error::Dbus(_))
        ));
        let error = client
            .delegated_controllers_with_proxy(&manager)
            .unwrap_err();
        // Properties.Get maps standard remote errors to zbus's FDO variants.
        match error {
            Error::Dbus(zbus::Error::FDO(error)) => {
                assert!(
                    matches!(error.as_ref(), zbus::fdo::Error::AccessDenied(message)
                    if message == "fixture denies DelegateControllers")
                );
                assert_eq!(
                    zbus::DBusError::name(error.as_ref()).as_str(),
                    "org.freedesktop.DBus.Error.AccessDenied"
                );
            }
            other => panic!("unexpected property error: {:?}", other),
        }
    }

    #[test]
    fn test_wait_timeout() {
        let timeout = Duration::from_millis(10);
        let result = async_io::block_on(with_timeout(
            futures_lite::future::pending::<crate::systemd::dbus::error::Result<()>>(),
            timeout,
            Error::JobWaitTimedOut {
                unit: "test.scope".to_string(),
                job: "/org/freedesktop/systemd1/job/1".to_string(),
                timeout,
            },
        ));

        match result {
            Err(Error::JobWaitTimedOut {
                unit,
                job,
                timeout: actual_timeout,
            }) => {
                assert_eq!(unit, "test.scope");
                assert_eq!(job, "/org/freedesktop/systemd1/job/1");
                assert_eq!(actual_timeout, timeout);
            }
            other => panic!("unexpected result: {:?}", other),
        }
    }

    fn test_unit() -> String {
        let rand_string: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(5)
            .map(char::from)
            .collect();
        format!("cri-pod{}.scope", rand_string)
    }

    #[macro_export]
    macro_rules! skip_if_no_systemd {
        () => {
            if $crate::tests::systemd_version().is_none() {
                eprintln!("Test skipped, no systemd?");
                return;
            }
        };
    }

    fn systemd_show(unit: &str) -> String {
        let output = Command::new("systemctl")
            .arg("show")
            .arg(unit)
            .output()
            .expect("Failed to execute systemctl show command");
        String::from_utf8_lossy(&output.stdout).to_string()
    }

    fn start_default_cgroup(pid: CgroupPid, unit: &'_ str) -> SystemdClient<'_> {
        let mut props = PropertiesBuilder::default_cgroup(TEST_SLICE, unit).build();
        props.push((PIDS, Value::Array(vec![pid.pid as u32].into())));
        let cgroup = SystemdClient::new(unit, props).unwrap();
        // Stop the unit if it exists.
        cgroup.stop().unwrap();

        // Write the current process to the cgroup.
        cgroup.start().unwrap();
        cgroup
    }

    fn stop_cgroup(cgroup: &SystemdClient) {
        cgroup.stop().unwrap();
    }

    #[test]
    fn test_start() {
        skip_if_not_root!();
        skip_if_no_systemd!();

        let v2 = hierarchies::is_cgroup2_unified_mode();
        let unit = test_unit();
        let mut child = spawn_sleep_inf();
        let cgroup = start_default_cgroup(CgroupPid::from(child.id() as u64), &unit);

        let base = expand_slice(TEST_SLICE).unwrap();

        let topology = crate::discovery::discover(&crate::discovery::HostPaths::default()).unwrap();
        let base_cpath = crate::model::CgroupPath::new(&base).unwrap();
        let full_base = if v2 {
            topology.cgroupfs_root.join(base_cpath.as_path())
        } else {
            topology
                .resolve_mount_point(Path::new("/sys/fs/cgroup/memory"))
                .join(base_cpath.as_path())
        };
        assert!(
            full_base.exists(),
            "Cgroup base path does not exist: {:?}",
            full_base
        );

        // PIDs
        let unit_cpath = crate::model::CgroupPath::new(&unit).unwrap();
        let cgroup_procs_path = full_base.join(unit_cpath.as_path()).join("cgroup.procs");
        for i in 0..5 {
            let content = fs::read_to_string(&cgroup_procs_path);
            if let Ok(content) = &content {
                if content.contains(&child.id().to_string()) {
                    break;
                }
            }
            // Retry attempts exhausted, resulting in failure
            if i == 4 {
                let content = content.as_ref().unwrap();
                assert!(
                    content.contains(&child.id().to_string()),
                    "Cgroup procs does not contain the child process ID"
                );
            }
            // Wait 500ms before next retrying
            sleep(Duration::from_millis(500));
        }

        // Check the unit from "systemctl show <unit>"
        let output = systemd_show(&cgroup.unit);

        // Slice
        assert!(
            output
                .lines()
                .any(|line| line == format!("Slice={}", TEST_SLICE)),
            "Slice not found"
        );
        // Delegate
        assert!(
            output.lines().any(|line| line == "Delegate=yes"),
            "Delegate not set"
        );
        // DelegateControllers
        // controllers: cpu cpuacct cpuset io blkio memory devices pids
        let controllers = output
            .lines()
            .find(|line| line.starts_with("DelegateControllers="))
            .map(|line| line.trim_start_matches("DelegateControllers="))
            .unwrap();
        let controllers = controllers.split(' ').collect::<Vec<&str>>();
        assert!(
            controllers.contains(&"cpu"),
            "DelegateControllers cpu not set"
        );
        assert!(
            controllers.contains(&"cpuset"),
            "DelegateControllers cpuset not set"
        );
        if v2 {
            assert!(
                controllers.contains(&"io"),
                "DelegateControllers io not set"
            );
        } else {
            assert!(
                controllers.contains(&"blkio"),
                "DelegateControllers blkio not set"
            );
        }
        assert!(
            controllers.contains(&"memory"),
            "DelegateControllers memory not set"
        );
        assert!(
            controllers.contains(&"pids"),
            "DelegateControllers pids not set"
        );

        // CPUAccounting
        assert!(
            output.lines().any(|line| line == "CPUAccounting=yes"),
            "CPUAccounting not set"
        );
        // IOAccounting for v2, and BlockIOAccounting for v1
        if v2 {
            assert!(
                output.lines().any(|line| line == "IOAccounting=yes"),
                "IOAccounting not set"
            );
        } else {
            assert!(
                output.lines().any(|line| line == "BlockIOAccounting=yes"),
                "BlockIOAccounting not set"
            );
        }
        // MemoryAccounting
        assert!(
            output.lines().any(|line| line == "MemoryAccounting=yes"),
            "MemoryAccounting not set"
        );
        // TasksAccounting
        assert!(
            output.lines().any(|line| line == "TasksAccounting=yes"),
            "TasksAccounting not set"
        );
        // ActiveState
        assert!(
            output.lines().any(|line| line == "ActiveState=active"),
            "Unit is not active"
        );

        stop_cgroup(&cgroup);
        child.wait().unwrap();
    }

    #[test]
    fn test_stop() {
        skip_if_not_root!();
        skip_if_no_systemd!();

        let unit = test_unit();
        let mut child = spawn_sleep_inf();
        let cgroup = start_default_cgroup(CgroupPid::from(child.id() as u64), &unit);

        // Check ActiveState: expected to be "active"
        let output = systemd_show(&cgroup.unit);
        assert!(
            output.lines().any(|line| line == "ActiveState=active"),
            "Unit is not active"
        );

        stop_cgroup(&cgroup);

        // Check ActiveState: expected to be "inactive"
        let output = systemd_show(&cgroup.unit);
        assert!(
            output.lines().any(|line| line == "ActiveState=inactive"),
            "Unit is not inactive"
        );

        child.wait().unwrap();
    }

    #[test]
    fn test_set_properties() {
        skip_if_not_root!();
        skip_if_no_systemd!();

        let unit = test_unit();
        let mut child = spawn_sleep_inf();
        let mut cgroup = start_default_cgroup(CgroupPid::from(child.id() as u64), &unit);

        let output = systemd_show(&cgroup.unit);
        assert!(
            output.lines().any(|line| line
                == format!(
                    "Description={} {}:{}",
                    DEFAULT_DESCRIPTION, TEST_SLICE, unit
                )),
            "Initial description not set correctly"
        );

        let properties = [(
            DESCRIPTION,
            Value::Str("kata-container1 description".into()),
        )];
        cgroup.set_properties(&properties).unwrap();
        assert!(cgroup.props.iter().any(|(k, v)| {
            k == &DESCRIPTION && v == &Value::Str("kata-container1 description".into())
        }));

        let output = systemd_show(&cgroup.unit);
        assert!(
            output
                .lines()
                .any(|line| line == "Description=kata-container1 description"),
            "Updated description not set correctly"
        );

        stop_cgroup(&cgroup);
        child.wait().unwrap();
    }

    #[test]
    fn test_freeze_and_thaw() {
        skip_if_not_root!();
        skip_if_no_systemd!();

        let v2 = hierarchies::is_cgroup2_unified_mode();
        let unit = test_unit();
        let mut child = spawn_yes();
        let cgroup = start_default_cgroup(CgroupPid::from(child.id() as u64), &unit);

        // Freeze the unit
        let freeze_result = cgroup.freeze();
        if !v2 {
            assert!(
                freeze_result.is_err(),
                "systemd should reject FreezeUnit on cgroup v1"
            );
            stop_cgroup(&cgroup);
            child.wait().unwrap();
            return;
        }
        freeze_result.unwrap();

        let pid = child.id() as u64;

        let stat_path = format!("/proc/{}/stat", pid);
        let content = fs::read_to_string(&stat_path).unwrap();
        // The process state is the third field, e.g.:
        // 1234 (bash) S 1233 ...
        //             ^
        let mut content_iter = content.split_whitespace();
        assert_eq!(
            content_iter.nth(2).unwrap(),
            "S",
            "Process should be in 'S' (sleeping) state after freezing"
        );

        // Thaw the unit
        cgroup.thaw().unwrap();

        // No more S now
        let content = fs::read_to_string(&stat_path).unwrap();
        let mut content_iter = content.split_whitespace();
        assert_ne!(
            content_iter.nth(2).unwrap(),
            "S",
            "Process should not be in 'S' (sleeping) state after thawing"
        );

        stop_cgroup(&cgroup);
        child.wait().unwrap();
    }

    #[test]
    fn test_exists() {
        skip_if_not_root!();
        skip_if_no_systemd!();

        let unit = test_unit();
        let mut child = spawn_sleep_inf();
        let cgroup = start_default_cgroup(CgroupPid::from(child.id() as u64), &unit);

        assert!(cgroup.exists(), "Cgroup should exist after starting");

        stop_cgroup(&cgroup);
        child.wait().unwrap();
    }

    #[test]
    fn test_add_process() {
        skip_if_not_root!();
        skip_if_no_systemd!();

        let v2 = hierarchies::is_cgroup2_unified_mode();
        let unit = test_unit();
        let mut child = spawn_sleep_inf();
        let cgroup = start_default_cgroup(CgroupPid::from(child.id() as u64), &unit);

        let mut child1 = spawn_sleep_inf();
        let pid1 = CgroupPid::from(child1.id() as u64);
        cgroup.add_process(pid1, "/").unwrap();

        let topology = crate::discovery::discover(&crate::discovery::HostPaths::default()).unwrap();
        let cgroup_root = if v2 {
            topology.cgroupfs_root.clone()
        } else {
            topology.resolve_mount_point(Path::new("/sys/fs/cgroup/memory"))
        };
        let slice_cpath = crate::model::CgroupPath::new(expand_slice(TEST_SLICE).unwrap()).unwrap();
        let unit_cpath = crate::model::CgroupPath::new(&unit).unwrap();
        let cgroup_procs_path = cgroup_root
            .join(slice_cpath.as_path())
            .join(unit_cpath.as_path())
            .join("cgroup.procs");
        for i in 0..5 {
            let content = fs::read_to_string(&cgroup_procs_path);
            if let Ok(content) = content {
                assert!(
                    content.contains(&child1.id().to_string()),
                    "Cgroup procs does not contain the child1 process ID"
                );
                break;
            }
            // Retry attempts exhausted, resulting in failure
            if i == 4 {
                content.unwrap();
            }
            // Wait 500ms before next retrying
            sleep(Duration::from_millis(500));
        }

        stop_cgroup(&cgroup);
        child.wait().unwrap();
        child1.wait().unwrap();
    }
}
