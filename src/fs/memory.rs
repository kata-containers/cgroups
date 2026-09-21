// Copyright (c) 2018 Levente Kurusa
// Copyright (c) 2020 Ant Group
//
// SPDX-License-Identifier: Apache-2.0 or MIT
//

//! This module contains the implementation of the `memory` cgroup subsystem.
//!
//! See the Kernel's documentation for more information about this subsystem, found at:
//!  [Documentation/cgroup-v1/memory.txt](https://www.kernel.org/doc/Documentation/cgroup-v1/memory.txt)
use log::warn;
use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::sync::mpsc::Receiver;

use crate::fs::error::ErrorKind::*;
use crate::fs::error::*;
use crate::fs::events;
use crate::fs::{optional_read, read_i64_from, read_string_from, read_u64_from};

use crate::fs::flat_keyed_to_hashmap;

use crate::fs::{
    ControllIdentifier, ControllerInternal, Controllers, CustomizedAttribute, MaxValue,
    MemoryResources, Resources, Subsystem, UpdateTracker,
};

/// A controller that allows controlling the `memory` subsystem of a Cgroup.
///
/// In essence, using the memory controller, the user can gather statistics about the memory usage
/// of the tasks in the control group. Additonally, one can also set powerful limits on their
/// memory usage.
#[derive(Debug, Clone)]
pub struct MemController {
    base: PathBuf,
    path: PathBuf,
    v2: bool,
}

#[derive(Default, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct SetMemory {
    pub low: Option<MaxValue>,
    pub high: Option<MaxValue>,
    pub min: Option<MaxValue>,
    pub max: Option<MaxValue>,
}

/// Controls statistics and controls about the OOM killer operating in this control group.
#[derive(Default, Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct OomControl {
    /// If true, the OOM killer has been disabled for the tasks in this control group.
    pub oom_kill_disable: bool,
    /// Is the OOM killer currently running for the tasks in the control group?
    pub under_oom: bool,
    /// How many tasks were killed by the OOM killer so far.
    pub oom_kill: u64,
}

fn parse_oom_control(s: String) -> Result<OomControl> {
    let mut oom_kill_disable = None;
    let mut under_oom = None;
    let mut oom_kill = None;

    // Parse records by key: oom_kill was added after the two control-state
    // records, and future kernels may append more counters.
    for line in s.lines() {
        let mut fields = line.split_whitespace();
        let key = fields.next().ok_or_else(|| Error::new(ParseError))?;
        let value = fields
            .next()
            .ok_or_else(|| Error::new(ParseError))?
            .parse::<u64>()
            .map_err(|e| Error::with_cause(ParseError, e))?;
        if fields.next().is_some() {
            return Err(Error::new(ParseError));
        }

        let duplicate = match key {
            "oom_kill_disable" if value <= 1 => oom_kill_disable.replace(value == 1).is_some(),
            "under_oom" if value <= 1 => under_oom.replace(value == 1).is_some(),
            "oom_kill" => oom_kill.replace(value).is_some(),
            "oom_kill_disable" | "under_oom" => return Err(Error::new(ParseError)),
            _ => false,
        };
        if duplicate {
            return Err(Error::new(ParseError));
        }
    }

    Ok(OomControl {
        oom_kill_disable: oom_kill_disable.ok_or_else(|| Error::new(ParseError))?,
        under_oom: under_oom.ok_or_else(|| Error::new(ParseError))?,
        // Older kernels do not expose this counter.
        oom_kill: oom_kill.unwrap_or(0),
    })
}

/// Contains statistics about the NUMA locality of the control group's tasks.
#[derive(Default, Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NumaStat {
    /// Total amount of pages used by the control group.
    pub total_pages: u64,
    /// Total amount of pages used by the control group, broken down by NUMA node.
    pub total_pages_per_node: Vec<u64>,
    /// Total amount of file pages used by the control group.
    pub file_pages: u64,
    /// Total amount of file pages used by the control group, broken down by NUMA node.
    pub file_pages_per_node: Vec<u64>,
    /// Total amount of anonymous pages used by the control group.
    pub anon_pages: u64,
    /// Total amount of anonymous pages used by the control group, broken down by NUMA node.
    pub anon_pages_per_node: Vec<u64>,
    /// Total amount of unevictable pages used by the control group.
    pub unevictable_pages: u64,
    /// Total amount of unevictable pages used by the control group, broken down by NUMA node.
    pub unevictable_pages_per_node: Vec<u64>,

    /// Same as `total_pages`, but includes the descedant control groups' number as well.
    pub hierarchical_total_pages: u64,
    /// Same as `total_pages_per_node`, but includes the descedant control groups' number as well.
    pub hierarchical_total_pages_per_node: Vec<u64>,
    /// Same as `file_pages`, but includes the descedant control groups' number as well.
    pub hierarchical_file_pages: u64,
    /// Same as `file_pages_per_node`, but includes the descedant control groups' number as well.
    pub hierarchical_file_pages_per_node: Vec<u64>,
    /// Same as `anon_pages`, but includes the descedant control groups' number as well.
    pub hierarchical_anon_pages: u64,
    /// Same as `anon_pages_per_node`, but includes the descedant control groups' number as well.
    pub hierarchical_anon_pages_per_node: Vec<u64>,
    /// Same as `unevictable`, but includes the descedant control groups' number as well.
    pub hierarchical_unevictable_pages: u64,
    /// Same as `unevictable_per_node`, but includes the descedant control groups' number as well.
    pub hierarchical_unevictable_pages_per_node: Vec<u64>,
}

fn parse_numa_stat(s: String) -> Result<NumaStat> {
    type NumaRecord = (u64, Vec<(u32, u64)>);

    fn parse_record(line: &str) -> Result<(String, NumaRecord)> {
        let mut fields = line.split_whitespace();
        let (key, value) = fields
            .next()
            .and_then(|field| field.split_once('='))
            .ok_or_else(|| Error::new(ParseError))?;
        if key.is_empty() {
            return Err(Error::new(ParseError));
        }
        let value = value
            .parse::<u64>()
            .map_err(|e| Error::with_cause(ParseError, e))?;

        let mut nodes = Vec::new();
        for field in fields {
            let (node, value) = field
                .split_once('=')
                .ok_or_else(|| Error::new(ParseError))?;
            let node = node
                .strip_prefix('N')
                .filter(|node| !node.is_empty() && node.bytes().all(|b| b.is_ascii_digit()))
                .ok_or_else(|| Error::new(ParseError))?
                .parse::<u32>()
                .map_err(|e| Error::with_cause(ParseError, e))?;
            if nodes.iter().any(|(seen, _)| *seen == node) {
                return Err(Error::new(ParseError));
            }
            let value = value
                .parse::<u64>()
                .map_err(|e| Error::with_cause(ParseError, e))?;
            nodes.push((node, value));
        }
        if nodes.is_empty() {
            return Err(Error::new(ParseError));
        }

        Ok((key.to_string(), (value, nodes)))
    }

    const BASE_KEYS: [&str; 4] = ["total", "file", "anon", "unevictable"];
    const HIERARCHICAL_KEYS: [&str; 4] = [
        "hierarchical_total",
        "hierarchical_file",
        "hierarchical_anon",
        "hierarchical_unevictable",
    ];

    let mut records = HashMap::new();
    for line in s.lines() {
        let (key, record) = parse_record(line)?;
        if records.insert(key, record).is_some() {
            return Err(Error::new(ParseError));
        }
    }

    for key in BASE_KEYS {
        if !records.contains_key(key) {
            return Err(Error::new(ParseError));
        }
    }
    // Some older kernels omit every hierarchical record. Treat that as one
    // supported format, but reject a partially emitted hierarchical group.
    let has_hierarchical = HIERARCHICAL_KEYS
        .iter()
        .any(|key| records.contains_key(*key));
    if has_hierarchical {
        for key in HIERARCHICAL_KEYS {
            if !records.contains_key(key) {
                return Err(Error::new(ParseError));
            }
        }
    }

    // Every counter in one kernel snapshot must describe the same NUMA nodes
    // in the same order; otherwise Vec<u64> would silently lose node identity.
    let expected_nodes: Vec<u32> = records["total"].1.iter().map(|(node, _)| *node).collect();
    for key in BASE_KEYS.iter().chain(HIERARCHICAL_KEYS.iter()) {
        if let Some((_, nodes)) = records.get(*key) {
            if !nodes
                .iter()
                .map(|(node, _)| *node)
                .eq(expected_nodes.iter().copied())
            {
                return Err(Error::new(ParseError));
            }
        }
    }

    let get = |key: &str| -> (u64, Vec<u64>) {
        records.get(key).map_or_else(
            || (0, Vec::new()),
            |(total, nodes)| (*total, nodes.iter().map(|(_, value)| *value).collect()),
        )
    };
    let total = get("total");
    let file = get("file");
    let anon = get("anon");
    let unevictable = get("unevictable");
    let hierarchical_total = get("hierarchical_total");
    let hierarchical_file = get("hierarchical_file");
    let hierarchical_anon = get("hierarchical_anon");
    let hierarchical_unevictable = get("hierarchical_unevictable");

    Ok(NumaStat {
        total_pages: total.0,
        total_pages_per_node: total.1,
        file_pages: file.0,
        file_pages_per_node: file.1,
        anon_pages: anon.0,
        anon_pages_per_node: anon.1,
        unevictable_pages: unevictable.0,
        unevictable_pages_per_node: unevictable.1,
        hierarchical_total_pages: hierarchical_total.0,
        hierarchical_total_pages_per_node: hierarchical_total.1,
        hierarchical_file_pages: hierarchical_file.0,
        hierarchical_file_pages_per_node: hierarchical_file.1,
        hierarchical_anon_pages: hierarchical_anon.0,
        hierarchical_anon_pages_per_node: hierarchical_anon.1,
        hierarchical_unevictable_pages: hierarchical_unevictable.0,
        hierarchical_unevictable_pages_per_node: hierarchical_unevictable.1,
    })
}

#[derive(Default, Debug, PartialEq, Eq, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MemoryStat {
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
    pub raw: HashMap<String, u64>,
}

fn parse_memory_stat(s: String) -> Result<MemoryStat> {
    let mut raw = HashMap::new();

    // Counter names vary between cgroup versions, kernel versions, and build
    // options. Do not require a fixed key set, but validate every record that
    // the kernel returned so a malformed value cannot become a silent zero.
    for line in s.lines() {
        let mut fields = line.split_whitespace();
        let key = fields.next().ok_or_else(|| Error::new(ParseError))?;
        let value = fields
            .next()
            .ok_or_else(|| Error::new(ParseError))?
            .parse::<u64>()
            .map_err(|e| Error::with_cause(ParseError, e))?;
        if fields.next().is_some() || raw.insert(key.to_string(), value).is_some() {
            return Err(Error::new(ParseError));
        }
    }
    if raw.is_empty() {
        return Err(Error::new(ParseError));
    }

    Ok(MemoryStat {
        cache: *raw.get("cache").unwrap_or(&0),
        rss: *raw.get("rss").unwrap_or(&0),
        rss_huge: *raw.get("rss_huge").unwrap_or(&0),
        shmem: *raw.get("shmem").unwrap_or(&0),
        mapped_file: *raw.get("mapped_file").unwrap_or(&0),
        dirty: *raw.get("dirty").unwrap_or(&0),
        writeback: *raw.get("writeback").unwrap_or(&0),
        swap: *raw.get("swap").unwrap_or(&0),
        pgpgin: *raw.get("pgpgin").unwrap_or(&0),
        pgpgout: *raw.get("pgpgout").unwrap_or(&0),
        pgfault: *raw.get("pgfault").unwrap_or(&0),
        pgmajfault: *raw.get("pgmajfault").unwrap_or(&0),
        inactive_anon: *raw.get("inactive_anon").unwrap_or(&0),
        active_anon: *raw.get("active_anon").unwrap_or(&0),
        inactive_file: *raw.get("inactive_file").unwrap_or(&0),
        active_file: *raw.get("active_file").unwrap_or(&0),
        unevictable: *raw.get("unevictable").unwrap_or(&0),
        hierarchical_memory_limit: *raw.get("hierarchical_memory_limit").unwrap_or(&0) as i64,
        hierarchical_memsw_limit: *raw.get("hierarchical_memsw_limit").unwrap_or(&0) as i64,
        total_cache: *raw.get("total_cache").unwrap_or(&0),
        total_rss: *raw.get("total_rss").unwrap_or(&0),
        total_rss_huge: *raw.get("total_rss_huge").unwrap_or(&0),
        total_shmem: *raw.get("total_shmem").unwrap_or(&0),
        total_mapped_file: *raw.get("total_mapped_file").unwrap_or(&0),
        total_dirty: *raw.get("total_dirty").unwrap_or(&0),
        total_writeback: *raw.get("total_writeback").unwrap_or(&0),
        total_swap: *raw.get("total_swap").unwrap_or(&0),
        total_pgpgin: *raw.get("total_pgpgin").unwrap_or(&0),
        total_pgpgout: *raw.get("total_pgpgout").unwrap_or(&0),
        total_pgfault: *raw.get("total_pgfault").unwrap_or(&0),
        total_pgmajfault: *raw.get("total_pgmajfault").unwrap_or(&0),
        total_inactive_anon: *raw.get("total_inactive_anon").unwrap_or(&0),
        total_active_anon: *raw.get("total_active_anon").unwrap_or(&0),
        total_inactive_file: *raw.get("total_inactive_file").unwrap_or(&0),
        total_active_file: *raw.get("total_active_file").unwrap_or(&0),
        total_unevictable: *raw.get("total_unevictable").unwrap_or(&0),
        raw,
    })
}

/// Contains statistics about the current usage of memory and swap (together, not seperately) by
/// the control group's tasks.
#[derive(Debug, Default, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MemSwap {
    /// How many times the limit has been hit.
    pub fail_cnt: u64,
    /// Memory and swap usage limit in bytes.
    pub limit_in_bytes: i64,
    /// Current usage of memory and swap in bytes.
    pub usage_in_bytes: u64,
    /// The maximum observed usage of memory and swap in bytes.
    pub max_usage_in_bytes: u64,
}

/// State of and statistics gathered by the kernel about the memory usage of the control group's
/// tasks.
#[derive(Debug, Default, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Memory {
    /// How many times the limit has been hit.
    pub fail_cnt: u64,
    /// The limit in bytes of the memory usage of the control group's tasks.
    pub limit_in_bytes: i64,
    /// The current usage of memory by the control group's tasks.
    pub usage_in_bytes: u64,
    /// The maximum observed usage of memory by the control group's tasks.
    pub max_usage_in_bytes: u64,
    /// Whether moving charges at immigrate is allowed.
    pub move_charge_at_immigrate: u64,
    /// Contains various statistics about the NUMA locality of the control group's tasks.
    ///
    /// The format of this field (as lifted from the kernel sources):
    /// ```text
    /// total=<total pages> N0=<node 0 pages> N1=<node 1 pages> ...
    /// file=<total file pages> N0=<node 0 pages> N1=<node 1 pages> ...
    /// anon=<total anon pages> N0=<node 0 pages> N1=<node 1 pages> ...
    /// unevictable=<total anon pages> N0=<node 0 pages> N1=<node 1 pages> ...
    /// hierarchical_<counter>=<counter pages> N0=<node 0 pages> N1=<node 1 pages> ...
    /// ```
    pub numa_stat: NumaStat,
    /// Various statistics and control information about the Out Of Memory killer.
    pub oom_control: OomControl,
    /// Allows setting a limit to memory usage which is enforced when the system (note, _not_ the
    /// control group) detects memory pressure.
    pub soft_limit_in_bytes: i64,
    /// Contains a wide array of statistics about the memory usage of the tasks in the control
    /// group.
    pub stat: MemoryStat,
    /// Set the tendency of the kernel to swap out parts of the address space consumed by the
    /// control group's tasks.
    ///
    /// Note that setting this to zero does *not* prevent swapping, use `mlock(2)` for that
    /// purpose.
    pub swappiness: u64,
    /// If set, then under OOM conditions, the kernel will try to reclaim memory from the children
    /// of the offending process too. By default, this is not allowed.
    pub use_hierarchy: u64,
}

/// The current state of and gathered statistics about the kernel's memory usage for TCP-related
/// data structures.
#[derive(Debug, Default, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Tcp {
    /// How many times the limit has been hit.
    pub fail_cnt: u64,
    /// The limit in bytes of the memory usage of the kernel's TCP buffers by control group's
    /// tasks.
    pub limit_in_bytes: i64,
    /// The current memory used by the kernel's TCP buffers related to these tasks.
    pub usage_in_bytes: u64,
    /// The observed maximum usage of memory by the kernel's TCP buffers (that originated from
    /// these tasks).
    pub max_usage_in_bytes: u64,
}

/// Gathered statistics and the current state of limitation of the kernel's memory usage. Note that
/// this is per-cgroup, so the kernel can of course use more memory, but it will fail operations by
/// these tasks if it would think that the limits here would be violated. It's important to note
/// that interrupts in particular might not be able to enforce these limits.
#[derive(Debug, Default, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Kmem {
    /// How many times the limit has been hit.
    pub fail_cnt: u64,
    /// The limit in bytes of the kernel memory used by the control group's tasks.
    pub limit_in_bytes: i64,
    /// The current usage of kernel memory used by the control group's tasks, in bytes.
    pub usage_in_bytes: u64,
    /// The maximum observed usage of kernel memory used by the control group's tasks, in bytes.
    pub max_usage_in_bytes: u64,
    /// Contains information about the memory usage of the kernel's caches, per control group.
    pub slabinfo: String,
}

impl ControllerInternal for MemController {
    fn control_type(&self) -> Controllers {
        Controllers::Mem
    }
    fn get_path(&self) -> &PathBuf {
        &self.path
    }
    fn get_path_mut(&mut self) -> &mut PathBuf {
        &mut self.path
    }
    fn get_base(&self) -> &PathBuf {
        &self.base
    }

    fn is_v2(&self) -> bool {
        self.v2
    }

    fn apply(&self, res: &Resources) -> Result<()> {
        // get the resources that apply to this controller
        let memres: &MemoryResources = &res.memory;
        let mut tracker = UpdateTracker::new();

        tracker.step_opt("memory.limit_in_bytes", memres.memory_hard_limit, |v| {
            self.set_limit(v)
        })?;
        tracker.step_opt(
            "memory.soft_limit_in_bytes",
            memres.memory_soft_limit,
            |v| self.set_soft_limit(v),
        )?;
        tracker.step_opt(
            "memory.kmem.limit_in_bytes",
            memres.kernel_memory_limit,
            |v| self.set_kmem_limit(v),
        )?;
        tracker.step_opt(
            "memory.memsw.limit_in_bytes",
            memres.memory_swap_limit,
            |v| self.set_memswap_limit(v),
        )?;
        tracker.step_opt(
            "memory.kmem.tcp.limit_in_bytes",
            memres.kernel_tcp_memory_limit,
            |v| self.set_tcp_limit(v),
        )?;
        tracker.step_opt("memory.swappiness", memres.swappiness, |v| {
            self.set_swappiness(v)
        })?;

        for (k, v) in &memres.attrs {
            tracker.step(k, || self.set(k, v))?;
        }

        Ok(())
    }
}

impl MemController {
    /// Contructs a new `MemController` with `root` serving as the root of the control group.
    pub fn new(point: PathBuf, root: PathBuf, v2: bool) -> Self {
        Self {
            base: root,
            path: point,
            v2,
        }
    }

    // for v2
    pub fn set_mem(&self, m: SetMemory) -> Result<()> {
        let values = vec![
            (m.high, "memory.high"),
            (m.low, "memory.low"),
            (m.max, "memory.max"),
            (m.min, "memory.min"),
        ];
        for value in values {
            let v = value.0;
            let f = value.1;
            if let Some(v) = v {
                let v = v.to_string();
                self.open_path(f, true).and_then(|mut file| {
                    file.write_all(v.as_ref()).map_err(|e| {
                        Error::with_cause(WriteFailed(f.to_string(), format!("{:?}", v)), e)
                    })
                })?;
            }
        }
        Ok(())
    }

    // for v2
    pub fn get_mem(&self) -> Result<SetMemory> {
        let m = SetMemory {
            high: self
                .get_max_value("memory.high")
                .map_or(Some(MaxValue::default()), Some),
            low: self
                .get_max_value("memory.low")
                .map_or(Some(MaxValue::Value(0)), Some),
            max: self
                .get_max_value("memory.max")
                .map_or(Some(MaxValue::default()), Some),
            min: self
                .get_max_value("memory.min")
                .map_or(Some(MaxValue::Value(0)), Some),
        };

        Ok(m)
    }

    /// Read the cgroup v2 memory protection and limit files without hiding
    /// filesystem or parse errors.
    pub fn try_get_mem(&self) -> Result<SetMemory> {
        Ok(SetMemory {
            high: Some(self.get_max_value("memory.high")?),
            low: Some(self.get_max_value("memory.low")?),
            max: Some(self.get_max_value("memory.max")?),
            min: Some(self.get_max_value("memory.min")?),
        })
    }

    fn memory_stat_v2(&self) -> Result<Memory> {
        let set = self.try_get_mem()?;

        Ok(Memory {
            fail_cnt: 0,
            limit_in_bytes: set.max.unwrap_or_default().to_i64(),
            usage_in_bytes: self
                .open_path("memory.current", false)
                .and_then(read_u64_from)?,
            max_usage_in_bytes: optional_read(
                self.open_path("memory.peak", false).and_then(read_u64_from),
            )?,
            move_charge_at_immigrate: 0,
            numa_stat: NumaStat::default(),
            oom_control: OomControl::default(),
            soft_limit_in_bytes: set.low.unwrap_or(MaxValue::Value(0)).to_i64(),
            stat: self
                .open_path("memory.stat", false)
                .and_then(read_string_from)
                .and_then(parse_memory_stat)?,
            swappiness: optional_read(
                self.open_path("memory.swap.current", false)
                    .and_then(read_u64_from),
            )?,
            use_hierarchy: 0,
        })
    }

    fn memory_stat_v2_legacy(&self) -> Memory {
        let set = self.get_mem().unwrap_or(SetMemory {
            low: Some(MaxValue::Value(0)),
            high: Some(MaxValue::default()),
            max: Some(MaxValue::default()),
            min: Some(MaxValue::Value(0)),
        });

        Memory {
            fail_cnt: 0,
            limit_in_bytes: set.max.unwrap().to_i64(),
            usage_in_bytes: self
                .open_path("memory.current", false)
                .and_then(read_u64_from)
                .unwrap_or(0),
            max_usage_in_bytes: self
                .open_path("memory.peak", false)
                .and_then(read_u64_from)
                .unwrap_or(0),
            move_charge_at_immigrate: 0,
            numa_stat: NumaStat::default(),
            oom_control: OomControl::default(),
            soft_limit_in_bytes: set.low.unwrap().to_i64(),
            stat: self
                .open_path("memory.stat", false)
                .and_then(read_string_from)
                .and_then(parse_memory_stat)
                .unwrap_or_default(),
            swappiness: self
                .open_path("memory.swap.current", false)
                .and_then(read_u64_from)
                .unwrap_or(0),
            use_hierarchy: 0,
        }
    }

    /// Gathers overall statistics (and the current state of) about the memory usage of the control
    /// group's tasks.
    ///
    /// See the individual fields for more explanation, and as always, remember to consult the
    /// kernel Documentation and/or sources.
    #[deprecated(note = "use `try_memory_stat` instead")]
    pub fn memory_stat(&self) -> Memory {
        if self.v2 {
            return self.memory_stat_v2_legacy();
        }

        Memory {
            fail_cnt: self
                .open_path("memory.failcnt", false)
                .and_then(read_u64_from)
                .unwrap_or(0),
            limit_in_bytes: self
                .open_path("memory.limit_in_bytes", false)
                .and_then(read_i64_from)
                .unwrap_or(0),
            usage_in_bytes: self
                .open_path("memory.usage_in_bytes", false)
                .and_then(read_u64_from)
                .unwrap_or(0),
            max_usage_in_bytes: self
                .open_path("memory.max_usage_in_bytes", false)
                .and_then(read_u64_from)
                .unwrap_or(0),
            move_charge_at_immigrate: self
                .open_path("memory.move_charge_at_immigrate", false)
                .and_then(read_u64_from)
                .unwrap_or(0),
            numa_stat: self
                .open_path("memory.numa_stat", false)
                .and_then(read_string_from)
                .and_then(parse_numa_stat)
                .unwrap_or_default(),
            oom_control: self
                .open_path("memory.oom_control", false)
                .and_then(read_string_from)
                .and_then(parse_oom_control)
                .unwrap_or_default(),
            soft_limit_in_bytes: self
                .open_path("memory.soft_limit_in_bytes", false)
                .and_then(read_i64_from)
                .unwrap_or(0),
            stat: self
                .open_path("memory.stat", false)
                .and_then(read_string_from)
                .and_then(parse_memory_stat)
                .unwrap_or_default(),
            swappiness: self
                .open_path("memory.swappiness", false)
                .and_then(read_u64_from)
                .unwrap_or(0),
            use_hierarchy: self
                .open_path("memory.use_hierarchy", false)
                .and_then(read_u64_from)
                .unwrap_or(0),
        }
    }

    /// Gathers overall statistics (and the current state of) about the memory usage of the control
    /// group's tasks, or an error if reading failed.
    pub fn try_memory_stat(&self) -> Result<Memory> {
        if self.v2 {
            return self.memory_stat_v2();
        }

        Ok(Memory {
            fail_cnt: self
                .open_path("memory.failcnt", false)
                .and_then(read_u64_from)?,
            limit_in_bytes: self
                .open_path("memory.limit_in_bytes", false)
                .and_then(read_i64_from)?,
            usage_in_bytes: self
                .open_path("memory.usage_in_bytes", false)
                .and_then(read_u64_from)?,
            max_usage_in_bytes: self
                .open_path("memory.max_usage_in_bytes", false)
                .and_then(read_u64_from)?,
            move_charge_at_immigrate: optional_read(
                self.open_path("memory.move_charge_at_immigrate", false)
                    .and_then(read_u64_from),
            )?,
            numa_stat: optional_read(
                self.open_path("memory.numa_stat", false)
                    .and_then(read_string_from)
                    .and_then(parse_numa_stat),
            )?,
            oom_control: self
                .open_path("memory.oom_control", false)
                .and_then(read_string_from)
                .and_then(parse_oom_control)?,
            soft_limit_in_bytes: self
                .open_path("memory.soft_limit_in_bytes", false)
                .and_then(read_i64_from)?,
            stat: self
                .open_path("memory.stat", false)
                .and_then(read_string_from)
                .and_then(parse_memory_stat)?,
            swappiness: optional_read(
                self.open_path("memory.swappiness", false)
                    .and_then(read_u64_from),
            )?,
            use_hierarchy: self
                .open_path("memory.use_hierarchy", false)
                .and_then(read_u64_from)?,
        })
    }

    /// Gathers information about the kernel memory usage of the control group's tasks.
    #[deprecated(note = "use `try_kmem_stat` instead")]
    pub fn kmem_stat(&self) -> Kmem {
        Kmem {
            fail_cnt: self
                .open_path("memory.kmem.failcnt", false)
                .and_then(read_u64_from)
                .unwrap_or(0),
            limit_in_bytes: self
                .open_path("memory.kmem.limit_in_bytes", false)
                .and_then(read_i64_from)
                .unwrap_or(-1),
            usage_in_bytes: self
                .open_path("memory.kmem.usage_in_bytes", false)
                .and_then(read_u64_from)
                .unwrap_or(0),
            max_usage_in_bytes: self
                .open_path("memory.kmem.max_usage_in_bytes", false)
                .and_then(read_u64_from)
                .unwrap_or(0),
            slabinfo: self
                .open_path("memory.kmem.slabinfo", false)
                .and_then(read_string_from)
                .unwrap_or_default(),
        }
    }

    /// Gathers information about the kernel memory usage of the control group's tasks, or an error if reading failed.
    pub fn try_kmem_stat(&self) -> Result<Kmem> {
        Ok(Kmem {
            fail_cnt: self
                .open_path("memory.kmem.failcnt", false)
                .and_then(read_u64_from)?,
            limit_in_bytes: self
                .open_path("memory.kmem.limit_in_bytes", false)
                .and_then(read_i64_from)?,
            usage_in_bytes: self
                .open_path("memory.kmem.usage_in_bytes", false)
                .and_then(read_u64_from)?,
            max_usage_in_bytes: self
                .open_path("memory.kmem.max_usage_in_bytes", false)
                .and_then(read_u64_from)?,
            slabinfo: optional_read(
                self.open_path("memory.kmem.slabinfo", false)
                    .and_then(read_string_from),
            )?,
        })
    }

    /// Gathers information about the control group's kernel memory usage where said memory is
    /// TCP-related.
    #[deprecated(note = "use `try_kmem_tcp_stat` instead")]
    pub fn kmem_tcp_stat(&self) -> Tcp {
        Tcp {
            fail_cnt: self
                .open_path("memory.kmem.tcp.failcnt", false)
                .and_then(read_u64_from)
                .unwrap_or(0),
            limit_in_bytes: self
                .open_path("memory.kmem.tcp.limit_in_bytes", false)
                .and_then(read_i64_from)
                .unwrap_or(0),
            usage_in_bytes: self
                .open_path("memory.kmem.tcp.usage_in_bytes", false)
                .and_then(read_u64_from)
                .unwrap_or(0),
            max_usage_in_bytes: self
                .open_path("memory.kmem.tcp.max_usage_in_bytes", false)
                .and_then(read_u64_from)
                .unwrap_or(0),
        }
    }

    /// Gathers information about the control group's kernel memory usage where said memory is
    /// TCP-related, or an error if reading failed.
    pub fn try_kmem_tcp_stat(&self) -> Result<Tcp> {
        Ok(Tcp {
            fail_cnt: self
                .open_path("memory.kmem.tcp.failcnt", false)
                .and_then(read_u64_from)?,
            limit_in_bytes: self
                .open_path("memory.kmem.tcp.limit_in_bytes", false)
                .and_then(read_i64_from)?,
            usage_in_bytes: self
                .open_path("memory.kmem.tcp.usage_in_bytes", false)
                .and_then(read_u64_from)?,
            max_usage_in_bytes: self
                .open_path("memory.kmem.tcp.max_usage_in_bytes", false)
                .and_then(read_u64_from)?,
        })
    }

    #[deprecated(note = "use `try_memswap_v2` instead")]
    pub fn memswap_v2(&self) -> MemSwap {
        MemSwap {
            fail_cnt: self
                .open_path("memory.swap.events", false)
                .and_then(flat_keyed_to_hashmap)
                .map(|x| *x.get("fail").unwrap_or(&0) as u64)
                .unwrap_or(0),
            limit_in_bytes: self
                .open_path("memory.swap.max", false)
                .and_then(read_i64_from)
                .unwrap_or(0),
            usage_in_bytes: self
                .open_path("memory.swap.current", false)
                .and_then(read_u64_from)
                .unwrap_or(0),
            max_usage_in_bytes: self
                .open_path("memory.swap.peak", false)
                .and_then(read_u64_from)
                .unwrap_or(0),
        }
    }

    pub fn try_memswap_v2(&self) -> Result<MemSwap> {
        Ok(MemSwap {
            fail_cnt: optional_read(
                self.open_path("memory.swap.events", false)
                    .and_then(flat_keyed_to_hashmap)
                    .map(|x| *x.get("fail").unwrap_or(&0) as u64),
            )?,
            limit_in_bytes: self.get_max_value("memory.swap.max")?.to_i64(),
            usage_in_bytes: self
                .open_path("memory.swap.current", false)
                .and_then(read_u64_from)?,
            max_usage_in_bytes: optional_read(
                self.open_path("memory.swap.peak", false)
                    .and_then(read_u64_from),
            )?,
        })
    }

    /// Gathers information about the memory usage of the control group including the swap usage
    /// (if any).
    #[deprecated(note = "use `try_memswap` instead")]
    #[allow(deprecated)]
    pub fn memswap(&self) -> MemSwap {
        if self.v2 {
            return self.memswap_v2();
        }

        MemSwap {
            fail_cnt: self
                .open_path("memory.memsw.failcnt", false)
                .and_then(read_u64_from)
                .unwrap_or(0),
            limit_in_bytes: self
                .open_path("memory.memsw.limit_in_bytes", false)
                .and_then(read_i64_from)
                .unwrap_or(0),
            usage_in_bytes: self
                .open_path("memory.memsw.usage_in_bytes", false)
                .and_then(read_u64_from)
                .unwrap_or(0),
            max_usage_in_bytes: self
                .open_path("memory.memsw.max_usage_in_bytes", false)
                .and_then(read_u64_from)
                .unwrap_or(0),
        }
    }

    /// Gathers information about the memory usage of the control group including the swap usage
    /// (if any), or an error if reading failed.
    pub fn try_memswap(&self) -> Result<MemSwap> {
        if self.v2 {
            return self.try_memswap_v2();
        }

        Ok(MemSwap {
            fail_cnt: self
                .open_path("memory.memsw.failcnt", false)
                .and_then(read_u64_from)?,
            limit_in_bytes: self
                .open_path("memory.memsw.limit_in_bytes", false)
                .and_then(read_i64_from)?,
            usage_in_bytes: self
                .open_path("memory.memsw.usage_in_bytes", false)
                .and_then(read_u64_from)?,
            max_usage_in_bytes: self
                .open_path("memory.memsw.max_usage_in_bytes", false)
                .and_then(read_u64_from)?,
        })
    }

    /// Reset the fail counter
    pub fn reset_fail_count(&self) -> Result<()> {
        self.open_path("memory.failcnt", true).and_then(|mut file| {
            file.write_all("0".to_string().as_ref()).map_err(|e| {
                Error::with_cause(
                    WriteFailed("memory.failcnt".to_string(), "0".to_string()),
                    e,
                )
            })
        })
    }

    /// Reset the kernel memory fail counter
    pub fn reset_kmem_fail_count(&self) -> Result<()> {
        // Ignore kmem because there is no kmem in cgroup v2
        if self.v2 {
            return Ok(());
        }

        self.open_path("memory.kmem.failcnt", true)
            .and_then(|mut file| {
                file.write_all("0".to_string().as_ref()).map_err(|e| {
                    Error::with_cause(
                        WriteFailed("memory.kmem.failcnt".to_string(), "0".to_string()),
                        e,
                    )
                })
            })
    }

    /// Reset the TCP related fail counter
    pub fn reset_tcp_fail_count(&self) -> Result<()> {
        // Ignore kmem because there is no kmem in cgroup v2
        if self.v2 {
            return Ok(());
        }

        self.open_path("memory.kmem.tcp.failcnt", true)
            .and_then(|mut file| {
                file.write_all("0".to_string().as_ref()).map_err(|e| {
                    Error::with_cause(
                        WriteFailed("memory.kmem.tcp.failcnt".to_string(), "0".to_string()),
                        e,
                    )
                })
            })
    }

    /// Reset the memory+swap fail counter
    pub fn reset_memswap_fail_count(&self) -> Result<()> {
        self.open_path("memory.memsw.failcnt", true)
            .and_then(|mut file| {
                file.write_all("0".to_string().as_ref()).map_err(|e| {
                    Error::with_cause(
                        WriteFailed("memory.memsw.failcnt".to_string(), "0".to_string()),
                        e,
                    )
                })
            })
    }

    /// Reset the max memory usage recorded
    pub fn reset_max_usage(&self) -> Result<()> {
        self.open_path("memory.max_usage_in_bytes", true)
            .and_then(|mut file| {
                file.write_all("0".to_string().as_ref()).map_err(|e| {
                    Error::with_cause(
                        WriteFailed("memory.max_usage_in_bytes".to_string(), "0".to_string()),
                        e,
                    )
                })
            })
    }

    /// Set the memory usage limit of the control group, in bytes.
    pub fn set_limit(&self, limit: i64) -> Result<()> {
        let mut file_name = "memory.limit_in_bytes";
        let mut limit_str = limit.to_string();
        if self.v2 {
            file_name = "memory.max";
            if limit == -1 {
                limit_str = "max".to_string();
            }
        }
        self.open_path(file_name, true).and_then(|mut file| {
            file.write_all(limit_str.as_ref())
                .map_err(|e| Error::with_cause(WriteFailed(file_name.to_string(), limit_str), e))
        })
    }

    /// Set the kernel memory limit of the control group, in bytes.
    pub fn set_kmem_limit(&self, limit: i64) -> Result<()> {
        // Ignore kmem because there is no kmem in cgroup v2
        if self.v2 {
            return Ok(());
        }

        self.open_path("memory.kmem.limit_in_bytes", true)
            .and_then(|mut file| {
                let r = file.write_all(limit.to_string().as_ref());
                match r {
                    Ok(()) => Ok(()),
                    Err(ref e) if e.raw_os_error() == Some(libc::EOPNOTSUPP) => {
                        warn!("memory.kmem.limit_in_bytes is unsupported by the kernel");
                        Ok(())
                    }
                    Err(e) => Err(Error::with_cause(
                        WriteFailed("memory.kmem.limit_in_bytes".to_string(), limit.to_string()),
                        e,
                    )),
                }
            })
    }

    /// Set the memory+swap limit of the control group, in bytes.
    pub fn set_memswap_limit(&self, limit: i64) -> Result<()> {
        let mut file_name = "memory.memsw.limit_in_bytes";
        let mut limit_str = limit.to_string();
        if self.v2 {
            file_name = "memory.swap.max";
            if limit == -1 {
                limit_str = "max".to_string();
            }
        }
        self.open_path(file_name, true).and_then(|mut file| {
            file.write_all(limit_str.as_ref())
                .map_err(|e| Error::with_cause(WriteFailed(file_name.to_string(), limit_str), e))
        })
    }

    /// Set how much kernel memory can be used for TCP-related buffers by the control group.
    pub fn set_tcp_limit(&self, limit: i64) -> Result<()> {
        // Ignore kmem because there is no kmem in cgroup v2
        if self.v2 {
            return Ok(());
        }

        self.open_path("memory.kmem.tcp.limit_in_bytes", true)
            .and_then(|mut file| {
                file.write_all(limit.to_string().as_ref()).map_err(|e| {
                    Error::with_cause(
                        WriteFailed(
                            "memory.kmem.tcp.limit_in_bytes".to_string(),
                            limit.to_string(),
                        ),
                        e,
                    )
                })
            })
    }

    /// Set the soft limit of the control group, in bytes.
    ///
    /// This limit is enforced when the system is nearing OOM conditions. Contrast this with the
    /// hard limit, which is _always_ enforced.
    pub fn set_soft_limit(&self, limit: i64) -> Result<()> {
        let mut file_name = "memory.soft_limit_in_bytes";
        if self.v2 {
            file_name = "memory.low"
        }
        self.open_path(file_name, true).and_then(|mut file| {
            file.write_all(limit.to_string().as_ref()).map_err(|e| {
                Error::with_cause(WriteFailed(file_name.to_string(), limit.to_string()), e)
            })
        })
    }

    /// Set how likely the kernel is to swap out parts of the address space used by the control
    /// group.
    ///
    /// Note that a value of zero does not imply that the process will not be swapped out.
    pub fn set_swappiness(&self, swp: u64) -> Result<()> {
        let mut file_name = "memory.swappiness";
        if self.v2 {
            file_name = "memory.swap.max"
        }

        self.open_path(file_name, true).and_then(|mut file| {
            file.write_all(swp.to_string().as_ref()).map_err(|e| {
                Error::with_cause(WriteFailed(file_name.to_string(), swp.to_string()), e)
            })
        })
    }

    pub fn disable_oom_killer(&self) -> Result<()> {
        if self.v2 {
            Err(Error::new(CgroupVersion))
        } else {
            self.open_path("memory.oom_control", true)
                .and_then(|mut file| {
                    file.write_all("1".to_string().as_ref()).map_err(|e| {
                        Error::with_cause(
                            WriteFailed("memory.oom_control".to_string(), "1".to_string()),
                            e,
                        )
                    })
                })
        }
    }

    pub fn register_oom_event(&self, key: &str) -> Result<Receiver<String>> {
        if self.v2 {
            events::notify_on_oom_v2(key, self.get_path())
        } else {
            events::notify_on_oom_v1(key, self.get_path())
        }
    }
}

impl ControllIdentifier for MemController {
    fn controller_type() -> Controllers {
        Controllers::Mem
    }
}

impl CustomizedAttribute for MemController {}

impl<'a> From<&'a Subsystem> for &'a MemController {
    fn from(sub: &'a Subsystem) -> &'a MemController {
        unsafe {
            match sub {
                Subsystem::Mem(c) => c,
                _ => {
                    assert_eq!(1, 0);
                    let v = std::mem::MaybeUninit::uninit();
                    v.assume_init()
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::fs::error::ErrorKind;
    use crate::fs::memory::{
        parse_memory_stat, parse_numa_stat, parse_oom_control, MemController, MemoryStat, NumaStat,
        OomControl,
    };
    use std::fs;
    use std::path::PathBuf;

    static GOOD_VALUE: &str = "\
total=51189 N0=51189 N1=123
file=50175 N0=50175 N1=123
anon=1014 N0=1014 N1=123
unevictable=0 N0=0 N1=123
hierarchical_total=1628573 N0=1628573 N1=123
hierarchical_file=858151 N0=858151 N1=123
hierarchical_anon=770402 N0=770402 N1=123
hierarchical_unevictable=20 N0=20 N1=123
";

    static GOOD_VALUE_NON_HIERARCHICAL: &str = "\
total=51189 N0=51189 N1=123
file=50175 N0=50175 N1=123
anon=1014 N0=1014 N1=123
unevictable=0 N0=0 N1=123
";

    static GOOD_OOMCONTROL_VAL_1: &str = "\
oom_kill_disable 0
oom_kill 1337
";

    static GOOD_OOMCONTROL_VAL_2: &str = "\
oom_kill_disable 0
under_oom 1
";

    static GOOD_OOMCONTROL_VAL_3: &str = "\
oom_kill_disable 0
under_oom 1
oom_kill 1337
";

    static GOOD_MEMORYSTAT_VAL: &str = "\
cache 178880512
rss 4206592
rss_huge 0
shmem 106496
mapped_file 7491584
dirty 114688
writeback 49152
swap 0
pgpgin 213928
pgpgout 169220
pgfault 87064
pgmajfault 202
inactive_anon 0
active_anon 4153344
inactive_file 84779008
active_file 94273536
unevictable 0
hierarchical_memory_limit 9223372036854771712
hierarchical_memsw_limit 9223372036854771712
total_cache 4200333312
total_rss 2927677440
total_rss_huge 0
total_shmem 590061568
total_mapped_file 1086164992
total_dirty 1769472
total_writeback 602112
total_swap 0
total_pgpgin 5267326291
total_pgpgout 5265586647
total_pgfault 9947902469
total_pgmajfault 25132
total_inactive_anon 585981952
total_active_anon 2928996352
total_inactive_file 1272135680
total_active_file 2338816000
total_unevictable 81920
";

    #[test]
    fn test_parse_numa_stat() {
        let ok = parse_numa_stat(GOOD_VALUE.to_string()).unwrap();
        assert_eq!(
            ok,
            NumaStat {
                total_pages: 51189,
                total_pages_per_node: vec![51189, 123],
                file_pages: 50175,
                file_pages_per_node: vec![50175, 123],
                anon_pages: 1014,
                anon_pages_per_node: vec![1014, 123],
                unevictable_pages: 0,
                unevictable_pages_per_node: vec![0, 123],

                hierarchical_total_pages: 1628573,
                hierarchical_total_pages_per_node: vec![1628573, 123],
                hierarchical_file_pages: 858151,
                hierarchical_file_pages_per_node: vec![858151, 123],
                hierarchical_anon_pages: 770402,
                hierarchical_anon_pages_per_node: vec![770402, 123],
                hierarchical_unevictable_pages: 20,
                hierarchical_unevictable_pages_per_node: vec![20, 123],
            }
        );
        let ok = parse_numa_stat(GOOD_VALUE_NON_HIERARCHICAL.to_string()).unwrap();
        assert_eq!(
            ok,
            NumaStat {
                total_pages: 51189,
                total_pages_per_node: vec![51189, 123],
                file_pages: 50175,
                file_pages_per_node: vec![50175, 123],
                anon_pages: 1014,
                anon_pages_per_node: vec![1014, 123],
                unevictable_pages: 0,
                unevictable_pages_per_node: vec![0, 123],

                hierarchical_total_pages: 0,
                hierarchical_total_pages_per_node: vec![],
                hierarchical_file_pages: 0,
                hierarchical_file_pages_per_node: vec![],
                hierarchical_anon_pages: 0,
                hierarchical_anon_pages_per_node: vec![],
                hierarchical_unevictable_pages: 0,
                hierarchical_unevictable_pages_per_node: vec![],
            }
        );
    }

    #[test]
    fn test_parse_numa_stat_rejects_incomplete_or_malformed_input() {
        let truncated = GOOD_VALUE.lines().take(7).collect::<Vec<_>>().join("\n");
        assert_eq!(
            parse_numa_stat(truncated).unwrap_err().kind(),
            &ErrorKind::ParseError
        );

        let invalid_number = GOOD_VALUE.replacen("file=50175", "file=invalid", 1);
        assert_eq!(
            parse_numa_stat(invalid_number).unwrap_err().kind(),
            &ErrorKind::ParseError
        );

        let missing_node_value = GOOD_VALUE.replacen("N0=1014", "N0", 1);
        assert_eq!(
            parse_numa_stat(missing_node_value).unwrap_err().kind(),
            &ErrorKind::ParseError
        );
    }

    #[test]
    fn test_parse_oom_control() {
        assert_eq!(
            parse_oom_control("".to_string()).unwrap_err().kind(),
            &ErrorKind::ParseError
        );
        assert_eq!(
            parse_oom_control(GOOD_OOMCONTROL_VAL_1.to_string())
                .unwrap_err()
                .kind(),
            &ErrorKind::ParseError
        );
        let ok = parse_oom_control(GOOD_OOMCONTROL_VAL_2.to_string()).unwrap();
        assert_eq!(
            ok,
            OomControl {
                oom_kill_disable: false,
                under_oom: true,
                oom_kill: 0,
            }
        );

        for malformed in [
            "oom_kill_disable invalid\nunder_oom 0\n",
            "oom_kill_disable 0\nunder_oom\n",
            "oom_kill_disable 0\nunder_oom 2\n",
        ] {
            assert_eq!(
                parse_oom_control(malformed.to_string()).unwrap_err().kind(),
                &ErrorKind::ParseError
            );
        }
        let ok = parse_oom_control(GOOD_OOMCONTROL_VAL_3.to_string()).unwrap();
        assert_eq!(
            ok,
            OomControl {
                oom_kill_disable: false,
                under_oom: true,
                oom_kill: 1337,
            }
        );
    }

    #[test]
    fn test_parse_memory_stat() {
        let ok = parse_memory_stat(GOOD_MEMORYSTAT_VAL.to_string()).unwrap();
        let raw = ok.raw.clone();
        assert_eq!(
            ok,
            MemoryStat {
                cache: 178880512,
                rss: 4206592,
                rss_huge: 0,
                shmem: 106496,
                mapped_file: 7491584,
                dirty: 114688,
                writeback: 49152,
                swap: 0,
                pgpgin: 213928,
                pgpgout: 169220,
                pgfault: 87064,
                pgmajfault: 202,
                inactive_anon: 0,
                active_anon: 4153344,
                inactive_file: 84779008,
                active_file: 94273536,
                unevictable: 0,
                hierarchical_memory_limit: 9223372036854771712,
                hierarchical_memsw_limit: 9223372036854771712,
                total_cache: 4200333312,
                total_rss: 2927677440,
                total_rss_huge: 0,
                total_shmem: 590061568,
                total_mapped_file: 1086164992,
                total_dirty: 1769472,
                total_writeback: 602112,
                total_swap: 0,
                total_pgpgin: 5267326291,
                total_pgpgout: 5265586647,
                total_pgfault: 9947902469,
                total_pgmajfault: 25132,
                total_inactive_anon: 585981952,
                total_active_anon: 2928996352,
                total_inactive_file: 1272135680,
                total_active_file: 2338816000,
                total_unevictable: 81920,
                raw,
            }
        );
    }

    #[test]
    fn test_parse_memory_stat_rejects_incomplete_or_malformed_records() {
        for malformed in ["", "cache\n", "cache invalid\n", "cache 1 extra\n"] {
            assert_eq!(
                parse_memory_stat(malformed.to_string()).unwrap_err().kind(),
                &ErrorKind::ParseError
            );
        }

        assert_eq!(
            parse_memory_stat("cache 1\ncache 2\n".to_string())
                .unwrap_err()
                .kind(),
            &ErrorKind::ParseError
        );
    }

    #[test]
    fn test_disable_oom_killer_v2() {
        // memory.oom_control does not exist in cgroup v2, so this must fail
        // cleanly instead of trying to write a non-existent file.
        let c = MemController::new(
            PathBuf::from("/sys/fs/cgroup/does-not-exist"),
            PathBuf::from("/sys/fs/cgroup"),
            true,
        );
        assert_eq!(
            c.disable_oom_killer().unwrap_err().kind(),
            &ErrorKind::CgroupVersion
        );
    }

    #[test]
    #[allow(deprecated)]
    fn test_legacy_memory_stats_preserve_readable_fields() {
        let path = std::env::temp_dir().join(format!(
            "cgroups-memory-legacy-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        fs::create_dir_all(&path).unwrap();

        fs::write(path.join("memory.usage_in_bytes"), "123\n").unwrap();
        let controller = MemController::new(path.clone(), path.clone(), false);

        // A missing sibling file must not erase a field that was read
        // successfully through the released best-effort API.
        let memory = controller.memory_stat();
        assert_eq!(memory.usage_in_bytes, 123);
        assert_eq!(memory.limit_in_bytes, 0);

        // Preserve the released kmem sentinel as well: absence means the
        // legacy unlimited/unsupported value, not a fabricated zero limit.
        assert_eq!(controller.kmem_stat().limit_in_bytes, -1);

        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn test_try_memory_v2_defaults_only_missing_optional_files() {
        let path = std::env::temp_dir().join(format!(
            "cgroups-memory-try-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        fs::create_dir_all(&path).unwrap();
        for (file, value) in [
            ("memory.high", "max\n"),
            ("memory.low", "0\n"),
            ("memory.max", "max\n"),
            ("memory.min", "0\n"),
            ("memory.current", "42\n"),
            ("memory.stat", "anon 42\n"),
        ] {
            fs::write(path.join(file), value).unwrap();
        }
        let controller = MemController::new(path.clone(), path.clone(), true);

        let stats = controller.try_memory_stat().unwrap();
        assert_eq!(stats.usage_in_bytes, 42);
        assert_eq!(stats.max_usage_in_bytes, 0);
        assert_eq!(stats.swappiness, 0);

        fs::write(path.join("memory.peak"), "invalid\n").unwrap();
        assert_eq!(
            controller.try_memory_stat().unwrap_err().kind(),
            &ErrorKind::ParseError
        );
        fs::remove_file(path.join("memory.peak")).unwrap();

        fs::write(path.join("memory.max"), "invalid\n").unwrap();
        assert_eq!(
            controller.try_memory_stat().unwrap_err().kind(),
            &ErrorKind::ParseError
        );

        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    #[allow(deprecated)]
    fn test_try_memory_v1_propagates_parser_errors() {
        let path = std::env::temp_dir().join(format!(
            "cgroups-memory-try-v1-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        fs::create_dir_all(&path).unwrap();
        for (file, value) in [
            ("memory.failcnt", "0\n"),
            ("memory.limit_in_bytes", "-1\n"),
            ("memory.usage_in_bytes", "0\n"),
            ("memory.max_usage_in_bytes", "0\n"),
            ("memory.oom_control", GOOD_OOMCONTROL_VAL_3),
            ("memory.soft_limit_in_bytes", "0\n"),
            ("memory.stat", "cache 0\n"),
            ("memory.use_hierarchy", "1\n"),
            ("memory.numa_stat", GOOD_VALUE),
        ] {
            fs::write(path.join(file), value).unwrap();
        }
        let controller = MemController::new(path.clone(), path.clone(), false);
        controller.try_memory_stat().unwrap();

        for (file, malformed, valid) in [
            (
                "memory.oom_control",
                "oom_kill_disable 0\nunder_oom invalid\n",
                GOOD_OOMCONTROL_VAL_3,
            ),
            (
                "memory.numa_stat",
                "total=0 N0=0\nfile=invalid N0=0\nanon=0 N0=0\nunevictable=0 N0=0\n",
                GOOD_VALUE,
            ),
            ("memory.stat", "cache invalid\n", "cache 0\n"),
        ] {
            fs::write(path.join(file), malformed).unwrap();
            assert_eq!(
                controller.try_memory_stat().unwrap_err().kind(),
                &ErrorKind::ParseError
            );

            // The released API remains best-effort and converts a malformed
            // optional/statistics section to that section's default value.
            controller.memory_stat();
            fs::write(path.join(file), valid).unwrap();
        }

        fs::remove_dir_all(path).unwrap();
    }
}
