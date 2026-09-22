// Copyright (c) 2026 Kata Contributors
//
// SPDX-License-Identifier: Apache-2.0 or MIT

//! Backend-independent resource values and state transitions.

/// The maximum value for CPU shares in cgroups v1.
pub const CPU_SHARES_V1_MAX: u64 = 262144;
/// The maximum value for CPU weight in cgroups v2.
pub const CPU_WEIGHT_V2_MAX: u64 = 10000;

/// The current state of the control group.
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum FreezerState {
    /// The processes in the control group are _not_ frozen.
    Thawed,
    /// The processes in the control group are in the processes of being frozen.
    Freezing,
    /// The processes in the control group are frozen.
    Frozen,
}
