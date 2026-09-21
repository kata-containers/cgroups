// Copyright (c) 2026 Ant Group
//
// SPDX-License-Identifier: Apache-2.0 or MIT

//! Core cgroup domain model: pure types and validation.

pub mod attachment;
pub mod path;

pub use attachment::AttachDestination;
pub use path::CgroupPath;
