// Copyright (c) 2026 Kata Contributors
//
// SPDX-License-Identifier: Apache-2.0 or MIT

#[derive(Debug, Default)]
pub struct CpuCgroupStats {
    pub cpu_acct: Option<CpuAcctStats>,
    pub cpu_throttling: Option<CpuThrottlingStats>,
}

#[derive(Debug, Default)]
pub struct CpuAcctStats {
    /// Usage in userspace, read from `cpuacct.stat` from the line starting
    /// with `user`. Set 0 if no data.
    pub user_usage: u64,
    /// Usage in kernelspace, read from `cpuacct.stat` from the line
    /// starting with `system`. Set 0 if no data.
    pub system_usage: u64,
    /// Total usage, read from `cpuacct.usage`. Set 0 if no data.
    pub total_usage: u64,
    /// Per-CPU usage, read from `cpuacct.usage_percpu`.
    pub usage_percpu: Vec<u64>,
}

#[derive(Debug, Default)]
pub struct CpuThrottlingStats {
    /// Periods, read from `cpu.stat` from the line starting with
    /// `nr_periods`. Set 0 if no data.
    pub periods: u64,
    /// Throttled periods, read from `cpu.stat` from the line starting with
    /// `nr_throttled`. Set 0 if no data.
    pub throttled_periods: u64,
    /// Throttled time, read from `cpu.stat` from the line starting with
    /// `throttled_time`. Set 0 if no data.
    pub throttled_time: u64,
}
