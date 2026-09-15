// Copyright (c) 2026 Ant Group
//
// SPDX-License-Identifier: Apache-2.0 or MIT

//! Core cgroup domain model: pure types and validation.

pub mod attachment;
pub mod path;
pub mod resources;

pub use attachment::AttachDestination;
pub use path::{validate_attribute_name, CgroupPath};
pub use resources::{
    BlkIoPatch, BlockDeviceThrottle, BlockDeviceWeight, CpuPatch, CpuSetPatch, DevicePatch,
    DeviceRule, HugePageLimit, HugePagePatch, InterfacePriority, MemoryPatch, NetworkPatch,
    PidsPatch, ResourcePatch, Update,
};
