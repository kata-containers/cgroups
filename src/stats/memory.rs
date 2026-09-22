// Copyright (c) 2026 Kata Contributors
//
// SPDX-License-Identifier: Apache-2.0 or MIT

#[derive(Debug, Default)]
pub struct MemoryCgroupStats {
    pub memory: Option<MemoryStats>,
    pub memory_swap: Option<MemoryStats>,
    pub kernel_memory: Option<MemoryStats>,

    /// Use hierarchy, read from `memory.use_hierarchy` in cgroups v1. Only
    /// available in cgroups v1.
    pub use_hierarchy: bool,

    // The following data is read from `memory.stat`, see also
    // `crate::fs::memory::MemoryStat::stat`.
    pub cache: u64,
    pub rss: u64,
    pub rss_huge: u64,
    pub shmem: u64,
    pub mapped_file: u64,
    pub dirty: u64,
    pub writeback: u64,
    pub swap: u64,
    pub pgpgin: u64,
    pub pgpgout: u64,
    pub pgfault: u64,
    pub pgmajfault: u64,
    pub inactive_anon: u64,
    pub active_anon: u64,
    pub inactive_file: u64,
    pub active_file: u64,
    pub unevictable: u64,
    pub hierarchical_memory_limit: i64,
    pub hierarchical_memsw_limit: i64,
    pub total_cache: u64,
    pub total_rss: u64,
    pub total_rss_huge: u64,
    pub total_shmem: u64,
    pub total_mapped_file: u64,
    pub total_dirty: u64,
    pub total_writeback: u64,
    pub total_swap: u64,
    pub total_pgpgin: u64,
    pub total_pgpgout: u64,
    pub total_pgfault: u64,
    pub total_pgmajfault: u64,
    pub total_inactive_anon: u64,
    pub total_active_anon: u64,
    pub total_inactive_file: u64,
    pub total_active_file: u64,
    pub total_unevictable: u64,
}

#[derive(Debug, Default)]
pub struct MemoryStats {
    /// Memory [swap] usage, read from `memory[.memsw].usage_in_bytes` in
    /// cgroups v1 and `memory[.swap].current` in cgroups v2.
    pub usage: u64,
    /// Maximum memory [swap] usage observed by cgroups, read from
    /// `memory[.memsw].max_usage_in_bytes` in cgroups v1 and
    /// `memory[.swap].peak` in cgroups v2.
    pub max_usage: u64,
    /// Memory [swap] limit, read from `memory[.memsw].limit_in_bytes` in
    /// cgroups v1 and `memory[.swap].max` in cgroups v2.
    pub limit: i64,
    /// Failure count, read from `memory[.memsw].failcnt`. Only available in
    /// cgroups v1.
    pub fail_cnt: u64,
}
