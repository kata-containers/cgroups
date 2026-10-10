// Copyright (c) 2020 And Group
//
// SPDX-License-Identifier: Apache-2.0 or MIT
//

//! Integration tests about the hugetlb subsystem
use cgroups_rs::core::CgroupPath;
use cgroups_rs::fs::error::*;
use cgroups_rs::fs::hugetlb::{self, HugeTlbController};
use cgroups_rs::fs::Cgroup;
use std::fs;

#[test]
fn test_hugetlb_sizes() {
    cgroups_rs::skip_if_not_root!();
    cgroups_rs::skip_if_cgroups_v2!();

    let h = cgroups_rs::fs::hierarchies::auto().unwrap();
    let cg = Cgroup::new(h, CgroupPath::new("test_hugetlb_sizes").unwrap()).unwrap();
    {
        let hugetlb_controller: &HugeTlbController = cg.controller_of().unwrap();
        let _ = hugetlb_controller.get_sizes();

        // test sizes count
        let sizes = hugetlb_controller.get_sizes();
        let sizes_count = fs::read_dir(hugetlb::HUGEPAGESIZE_DIR).unwrap().count();
        assert_eq!(sizes.len(), sizes_count);

        for size in sizes {
            let supported = hugetlb_controller.size_supported(&size);
            assert!(supported);
            assert_no_error(hugetlb_controller.failcnt(&size));
            assert_no_error(hugetlb_controller.limit_in_bytes(&size));
            assert_no_error(hugetlb_controller.usage_in_bytes(&size));
            assert_no_error(hugetlb_controller.max_usage_in_bytes(&size));
        }
    }
    cg.delete().unwrap();
}

fn assert_no_error(r: Result<u64>) {
    assert!(r.is_ok())
}
