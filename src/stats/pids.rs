// Copyright (c) 2026 Kata Contributors
//
// SPDX-License-Identifier: Apache-2.0 or MIT

#[derive(Debug, Default)]
pub struct PidsCgroupStats {
    /// Current number of processes in the cgroup, read from `pids.current`.
    pub current: u64,
    /// Maximum number of processes in the cgroup, read from `pids.limit`.
    pub limit: i64,
}
