// Copyright (c) 2026 Kata Contributors
//
// SPDX-License-Identifier: Apache-2.0 or MIT

#[derive(Debug, Default)]
pub struct BlkioCgroupStats {
    pub io_service_bytes_recursive: Vec<BlkioStat>,
    pub io_serviced_recursive: Vec<BlkioStat>,
    pub io_queued_recursive: Vec<BlkioStat>,
    pub io_service_time_recursive: Vec<BlkioStat>,
    pub io_wait_time_recursive: Vec<BlkioStat>,
    pub io_merged_recursive: Vec<BlkioStat>,
    pub io_time_recursive: Vec<BlkioStat>,
    pub sectors_recursive: Vec<BlkioStat>,
}

#[derive(Debug, Default)]
pub struct BlkioStat {
    pub major: u64,
    pub minor: u64,
    pub op: String,
    pub value: u64,
}
