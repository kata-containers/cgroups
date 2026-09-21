// Copyright (c) 2026 Kata Contributors
//
// SPDX-License-Identifier: Apache-2.0 or MIT

//! Backend-independent cgroup types, validation, errors, and host discovery.

pub mod attachment;
pub mod discovery;
pub mod error;
pub mod path;
pub mod resources;

pub use attachment::CgroupPid;
pub use discovery::{
    parse_membership, parse_membership_bytes, parse_mountinfo, parse_mountinfo_bytes,
    CgroupMembership, CgroupMountTable, MembershipRecord, MountRecord,
};
pub use error::{CoreError, CoreResult, ParseMembershipError, ParseMountError, PathError};
pub use path::CgroupPath;
pub use resources::{FreezerState, CPU_SHARES_V1_MAX, CPU_WEIGHT_V2_MAX};
