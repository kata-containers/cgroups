// SPDX-License-Identifier: Apache-2.0 or MIT

//! Host discovery: pure parsers for kernel text formats.
//!
//! The parsers in this module transform supplied text into [`MountTable`]
//! and [`Membership`] values and never perform I/O. Reading the host
//! (`/proc` and the cgroup filesystem) belongs to the topology layer that
//! assembles a snapshot from these pure results.

pub mod membership;
pub mod mountinfo;

pub use membership::{parse_membership, Membership, MembershipRecord};
pub use mountinfo::{parse_mountinfo, MountRecord, MountTable};
