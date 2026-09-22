// Copyright (c) 2026 Kata Contributors
//
// SPDX-License-Identifier: Apache-2.0 or MIT

//! Backend-independent cgroup types and resource values.

pub mod attachment;
pub mod resources;

pub use attachment::CgroupPid;
pub use resources::{FreezerState, CPU_SHARES_V1_MAX, CPU_WEIGHT_V2_MAX};
