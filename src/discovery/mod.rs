// SPDX-License-Identifier: Apache-2.0 or MIT

//! Host discovery: pure parsers for kernel text formats and the topology
//! snapshot assembled from them.
//!
//! The parsers in [`mountinfo`] and [`membership`] transform supplied
//! text into [`MountTable`] and [`Membership`] values and never perform
//! I/O. [`topology`] is the layer that reads the host once, resolves the
//! cgroup version verdict, and returns an immutable
//! [`CgroupTopology`] shared through `Arc`.

pub mod membership;
pub mod mountinfo;
pub mod topology;

pub use membership::{parse_membership, Membership, MembershipRecord};
pub use mountinfo::{parse_mountinfo, MountRecord, MountTable};
pub use topology::{discover, CgroupTopology, CgroupVersion, ControllerSet, HostPaths};
