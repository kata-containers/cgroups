// Copyright (c) 2026 Kata Contributors
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use std::collections::HashMap;

/// A structure representing the statistics of the `hugetlb` subsystem of a
/// Cgroup. The key is the huge page size, and the value is the statistics
/// for that size.
pub type HugeTlbCgroupStats = HashMap<String, HugeTlbStat>;

#[derive(Debug, Default)]
pub struct HugeTlbStat {
    pub usage: u64,
    pub max_usage: u64,
    pub fail_cnt: u64,
}
