// Copyright (c) 2026 Kata Contributors
//
// SPDX-License-Identifier: Apache-2.0 or MIT
//

//! Checked Linux process identifier.
//!
//! In Linux systems programming, process identifiers are represented in kernel
//! space by `pid_t`, which is a signed 32-bit integer (`int`). Valid user-space
//! process identifiers are strictly positive integers in the range `1 ..= 0x7fff_ffff`
//! (`i32::MAX`).
//!
//! PID 0 designates the kernel idle process (swapper) and cannot be migrated to
//! any cgroup. PIDs exceeding `i32::MAX` are out of range for Linux `pid_t` and
//! could cause silent truncation or integer overflow when passed through D-Bus
//! (`au` array of `uint32`) or pseudo-filesystem `/proc/<pid>` paths.
//!
//! `ProcessId` wraps a validated `u32` ensuring at type boundaries that these
//! kernel invariants hold.

use std::convert::TryFrom;
use std::fmt;

use crate::error::CoreError;
use crate::CgroupPid;

/// A validated Linux process identifier.
///
/// Guaranteed to be in the positive range `1 ..= i32::MAX as u32`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProcessId(u32);

impl ProcessId {
    /// The maximum valid Linux `pid_t` value (`0x7fff_ffff`).
    pub const MAX: u32 = i32::MAX as u32;

    /// Validate and construct a `ProcessId` from a `u32`.
    ///
    /// # Errors
    ///
    /// Returns [`CoreError::InvalidProcessId`] if `raw == 0` or `raw > i32::MAX as u32`.
    pub fn new(raw: u32) -> Result<Self, CoreError> {
        if raw == 0 {
            return Err(CoreError::InvalidProcessId {
                raw: 0,
                reason: "process ID cannot be zero",
            });
        }
        if raw > Self::MAX {
            return Err(CoreError::InvalidProcessId {
                raw: raw as u64,
                reason: "process ID exceeds Linux pid_t positive range (0x7fff_ffff)",
            });
        }
        Ok(Self(raw))
    }

    /// Return the inner raw `u32` value.
    pub fn get(self) -> u32 {
        self.0
    }
}

impl TryFrom<u32> for ProcessId {
    type Error = CoreError;

    fn try_from(val: u32) -> Result<Self, Self::Error> {
        Self::new(val)
    }
}

impl TryFrom<u64> for ProcessId {
    type Error = CoreError;

    fn try_from(val: u64) -> Result<Self, Self::Error> {
        if val == 0 {
            return Err(CoreError::InvalidProcessId {
                raw: 0,
                reason: "process ID cannot be zero",
            });
        }
        if val > Self::MAX as u64 {
            return Err(CoreError::InvalidProcessId {
                raw: val,
                reason: "process ID exceeds Linux pid_t positive range (0x7fff_ffff)",
            });
        }
        Ok(Self(val as u32))
    }
}

impl TryFrom<i32> for ProcessId {
    type Error = CoreError;

    fn try_from(val: i32) -> Result<Self, Self::Error> {
        if val <= 0 {
            return Err(CoreError::InvalidProcessId {
                raw: val as u64,
                reason: "process ID must be strictly positive",
            });
        }
        Ok(Self(val as u32))
    }
}

impl TryFrom<CgroupPid> for ProcessId {
    type Error = CoreError;

    fn try_from(pid: CgroupPid) -> Result<Self, Self::Error> {
        Self::try_from(pid.pid)
    }
}

impl From<ProcessId> for u32 {
    fn from(pid: ProcessId) -> Self {
        pid.get()
    }
}

impl From<ProcessId> for CgroupPid {
    fn from(pid: ProcessId) -> Self {
        CgroupPid {
            pid: pid.get() as u64,
        }
    }
}

impl fmt::Display for ProcessId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_process_ids() {
        let p1 = ProcessId::new(1).unwrap();
        assert_eq!(p1.get(), 1);
        assert_eq!(p1.to_string(), "1");

        let p_mid = ProcessId::new(1000).unwrap();
        assert_eq!(p_mid.get(), 1000);

        let p_max = ProcessId::new(ProcessId::MAX).unwrap();
        assert_eq!(p_max.get(), i32::MAX as u32);
    }

    #[test]
    fn test_zero_rejected() {
        assert!(ProcessId::new(0).is_err());
        assert!(ProcessId::try_from(0u32).is_err());
        assert!(ProcessId::try_from(0u64).is_err());
        assert!(ProcessId::try_from(0i32).is_err());
        assert!(ProcessId::try_from(CgroupPid::from(0u64)).is_err());
    }

    #[test]
    fn test_negative_i32_rejected() {
        assert!(ProcessId::try_from(-1i32).is_err());
        assert!(ProcessId::try_from(i32::MIN).is_err());
    }

    #[test]
    fn test_overflow_rejected() {
        let overflow_u32 = ProcessId::MAX + 1;
        assert!(ProcessId::new(overflow_u32).is_err());
        assert!(ProcessId::try_from(overflow_u32).is_err());

        let overflow_u64 = u64::from(ProcessId::MAX) + 1;
        assert!(ProcessId::try_from(overflow_u64).is_err());
        assert!(ProcessId::try_from(u64::MAX).is_err());
        assert!(ProcessId::try_from(CgroupPid::from(u64::MAX)).is_err());
    }

    #[test]
    fn test_conversion_to_and_from_cgroup_pid() {
        let raw = 12345u64;
        let cpid = CgroupPid::from(raw);
        let pid = ProcessId::try_from(cpid).unwrap();
        assert_eq!(pid.get(), 12345);

        let roundtrip: CgroupPid = pid.into();
        assert_eq!(roundtrip.pid, raw);
    }

    #[test]
    fn test_ordering_and_hashing() {
        let p1 = ProcessId::new(10).unwrap();
        let p2 = ProcessId::new(20).unwrap();
        assert!(p1 < p2);

        let mut set = std::collections::HashSet::new();
        set.insert(p1);
        assert!(set.contains(&p1));
        assert!(!set.contains(&p2));
    }
}
