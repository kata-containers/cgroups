// Copyright (c) 2018 Levente Kurusa
// Copyright (c) 2020 And Group
//
// SPDX-License-Identifier: Apache-2.0 or MIT
//

//! Some simple tests covering the builder pattern for control groups.
use cgroups_rs::core::CgroupPath;
use cgroups_rs::fs::blkio::*;
use cgroups_rs::fs::cpu::*;
use cgroups_rs::fs::devices::*;
use cgroups_rs::fs::hugetlb::*;
use cgroups_rs::fs::memory::*;
use cgroups_rs::fs::net_cls::*;
use cgroups_rs::fs::pid::*;
use cgroups_rs::fs::*;

#[test]
pub fn test_cpu_res_build() {
    cgroups_rs::skip_if_not_root!();

    let h = cgroups_rs::fs::hierarchies::auto().unwrap();
    let cg = Cgroup::builder(h, CgroupPath::new("test_cpu_res_build").unwrap())
        .create()
        .unwrap();
    let mut resources = Resources::default();
    resources.cpu.shares = Some(85);
    cg.apply(&resources).unwrap();

    {
        let cpu: &CpuController = cg.controller_of().unwrap();
        assert!(cpu.shares().is_ok());
        assert_eq!(cpu.shares().unwrap(), 85);
    }

    cg.delete().unwrap();
}

#[test]
pub fn test_memory_res_build() {
    cgroups_rs::skip_if_not_root!();

    let h = cgroups_rs::fs::hierarchies::auto().unwrap();
    let cg = Cgroup::builder(h, CgroupPath::new("test_memory_res_build").unwrap())
        .create()
        .unwrap();
    let mut resources = Resources::default();
    resources.memory.kernel_memory_limit = Some(128 * 1024 * 1024);
    if !cg.v2() {
        // Only v1 supports a per-cgroup swappiness setting.
        resources.memory.swappiness = Some(70);
    }
    resources.memory.memory_hard_limit = Some(1024 * 1024 * 1024);
    cg.apply(&resources).unwrap();

    {
        let c: &MemController = cg.controller_of().unwrap();
        if !c.v2() {
            // Note: we don't tests the value of c.kmem_stat().limit_in_bytes because on Linux
            // kernel >= 5.16 setting this value is unsupported.
            assert_eq!(c.memory_stat().swappiness, 70);
        }
        assert_eq!(c.memory_stat().limit_in_bytes, 1024 * 1024 * 1024);
    }

    cg.delete().unwrap();
}

#[test]
pub fn test_pid_res_build() {
    cgroups_rs::skip_if_not_root!();

    let h = cgroups_rs::fs::hierarchies::auto().unwrap();
    let cg = Cgroup::builder(h, CgroupPath::new("test_pid_res_build").unwrap())
        .create()
        .unwrap();
    let mut resources = Resources::default();
    resources.pid.maximum_number_of_processes = Some(MaxValue::Value(123));
    cg.apply(&resources).unwrap();

    {
        let c: &PidController = cg.controller_of().unwrap();
        assert!(c.get_pid_max().is_ok());
        assert_eq!(c.get_pid_max().unwrap(), MaxValue::Value(123));
    }

    cg.delete().unwrap();
}

#[test]
#[ignore] // ignore this test for now, not sure why my kernel doesn't like it
pub fn test_devices_res_build() {
    cgroups_rs::skip_if_not_root!();

    let h = cgroups_rs::fs::hierarchies::auto().unwrap();
    let cg = Cgroup::builder(h, CgroupPath::new("test_devices_res_build").unwrap())
        .create()
        .unwrap();
    let mut resources = Resources::default();
    resources.devices.devices.push(DeviceResource {
        allow: true,
        devtype: DeviceType::Char,
        major: 1,
        minor: 6,
        access: vec![DevicePermissions::Read],
    });
    cg.apply(&resources).unwrap();

    {
        let c: &DevicesController = cg.controller_of().unwrap();
        assert!(c.allowed_devices().is_ok());
        assert_eq!(
            c.allowed_devices().unwrap(),
            vec![DeviceResource {
                allow: true,
                devtype: DeviceType::Char,
                major: 1,
                minor: 6,
                access: vec![DevicePermissions::Read],
            }]
        );
    }
    cg.delete().unwrap();
}

#[test]
pub fn test_network_res_build() {
    cgroups_rs::skip_if_not_root!();
    cgroups_rs::skip_if_cgroups_v2!();

    let h = cgroups_rs::fs::hierarchies::auto().unwrap();
    let cg = Cgroup::builder(h, CgroupPath::new("test_network_res_build").unwrap())
        .create()
        .unwrap();
    let mut resources = Resources::default();
    resources.network.class_id = Some(1337);
    cg.apply(&resources).unwrap();

    {
        let c: &NetClsController = cg.controller_of().unwrap();
        assert!(c.get_class().is_ok());
        assert_eq!(c.get_class().unwrap(), 1337);
    }
    cg.delete().unwrap();
}

#[test]
pub fn test_hugepages_res_build() {
    cgroups_rs::skip_if_not_root!();
    cgroups_rs::skip_if_cgroups_v2!();

    let h = cgroups_rs::fs::hierarchies::auto().unwrap();
    let cg = Cgroup::builder(h, CgroupPath::new("test_hugepages_res_build").unwrap())
        .create()
        .unwrap();
    let mut resources = Resources::default();
    resources.hugepages.limits.push(HugePageResource {
        size: "2MB".to_string(),
        limit: 4 * 2 * 1024 * 1024,
    });
    cg.apply(&resources).unwrap();

    {
        let c: &HugeTlbController = cg.controller_of().unwrap();
        assert!(c.limit_in_bytes("2MB").is_ok());
        assert_eq!(c.limit_in_bytes("2MB").unwrap(), 4 * 2 * 1024 * 1024);
    }
    cg.delete().unwrap();
}

#[test]
#[ignore] // high version kernel not support `blkio.weight`
pub fn test_blkio_res_build() {
    cgroups_rs::skip_if_not_root!();

    let h = cgroups_rs::fs::hierarchies::auto().unwrap();
    let cg = Cgroup::builder(h, CgroupPath::new("test_blkio_res_build").unwrap())
        .create()
        .unwrap();
    let mut resources = Resources::default();
    resources.blkio.weight = Some(100);
    cg.apply(&resources).unwrap();

    {
        let c: &BlkIoController = cg.controller_of().unwrap();
        assert_eq!(c.blkio().weight, 100);
    }
    cg.delete().unwrap();
}
