// Copyright (c) 2026 Kata Contributors
//
// SPDX-License-Identifier: Apache-2.0 or MIT

pub mod blkio;
pub mod cpu;
pub mod hugetlb;
pub mod memory;
pub mod pids;

pub use blkio::{BlkioCgroupStats, BlkioStat};
pub use cpu::{CpuAcctStats, CpuCgroupStats, CpuThrottlingStats};
pub use hugetlb::{HugeTlbCgroupStats, HugeTlbStat};
pub use memory::{MemoryCgroupStats, MemoryStats};
pub use pids::PidsCgroupStats;

#[derive(Debug, Default)]
pub struct CgroupStats {
    pub cpu: CpuCgroupStats,
    pub memory: MemoryCgroupStats,
    pub pids: PidsCgroupStats,
    pub blkio: BlkioCgroupStats,
    pub hugetlb: HugeTlbCgroupStats,
}
