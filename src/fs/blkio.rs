// Copyright (c) 2018 Levente Kurusa
// Copyright (c) 2020 And Group
//
// SPDX-License-Identifier: Apache-2.0 or MIT
//

//! This module contains the implementation of the `blkio` cgroup subsystem.
//!
//! See the Kernel's documentation for more information about this subsystem, found at:
//!  [Documentation/cgroup-v1/blkio-controller.txt](https://www.kernel.org/doc/Documentation/cgroup-v1/blkio-controller.txt)
use std::io::Write;
use std::path::PathBuf;

use crate::fs::error::ErrorKind::*;
use crate::fs::error::*;

use crate::fs::{optional_read, read_string_from, read_u64_from};
use crate::fs::{
    BlkIoResources, ControllIdentifier, ControllerInternal, Controllers, CustomizedAttribute,
    Resources, Subsystem, UpdateTracker,
};

/// A controller that allows controlling the `blkio` subsystem of a Cgroup.
///
/// In essence, using the `blkio` controller one can limit and throttle the tasks' usage of block
/// devices in the control group.
#[derive(Debug, Clone)]
pub struct BlkIoController {
    base: PathBuf,
    path: PathBuf,
    v2: bool,
}

#[derive(Eq, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// Per-device information
pub struct BlkIoData {
    /// The major number of the device.
    pub major: i16,
    /// The minor number of the device.
    pub minor: i16,
    /// The data that is associated with the device.
    pub data: u64,
}

#[derive(Eq, PartialEq, Debug, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// Per-device activity from the control group.
pub struct IoService {
    /// The major number of the device.
    pub major: i16,
    /// The minor number of the device.
    pub minor: i16,
    /// How many items were read from the device.
    pub read: u64,
    /// How many items were written to the device.
    pub write: u64,
    /// How many items were synchronously transferred.
    pub sync: u64,
    /// How many items were asynchronously transferred.
    pub r#async: u64,
    /// How many items were discarded.
    pub discard: u64,
    /// Total number of items transferred.
    pub total: u64,
}

#[derive(Eq, PartialEq, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
/// Per-device activity from the control group.
/// Only for cgroup v2
pub struct IoStat {
    /// The major number of the device.
    pub major: i16,
    /// The minor number of the device.
    pub minor: i16,
    /// How many bytes were read from the device.
    pub rbytes: u64,
    /// How many bytes were written to the device.
    pub wbytes: u64,
    /// How many iops were read from the device.
    pub rios: u64,
    /// How many iops were written to the device.
    pub wios: u64,
    /// How many discard bytes were read from the device.
    pub dbytes: u64,
    /// How many discard iops were written to the device.
    pub dios: u64,
}

fn parse_io_service(s: String) -> Result<Vec<IoService>> {
    let mut io_services = Vec::<IoService>::new();
    let mut io_service = IoService::default();

    for line in s.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.is_empty() || (fields.len() == 2 && fields[0] == "Total") {
            continue;
        }
        if fields.len() != 3 {
            return Err(Error::new(ParseError));
        }
        let (major, minor) = fields[0]
            .split_once(':')
            .ok_or_else(|| Error::new(ParseError))?;
        let major = major.parse::<i16>().map_err(|_| Error::new(ParseError))?;
        let minor = minor.parse::<i16>().map_err(|_| Error::new(ParseError))?;

        if (major != io_service.major || minor != io_service.minor) && io_service.major != 0 {
            // new block device
            io_services.push(io_service);
            io_service = IoService::default();
        }

        io_service.major = major;
        io_service.minor = minor;

        let val = fields[2]
            .parse::<u64>()
            .map_err(|_| Error::new(ParseError))?;

        match fields[1] {
            "Read" => io_service.read = val,
            "Write" => io_service.write = val,
            "Sync" => io_service.sync = val,
            "Async" => io_service.r#async = val,
            "Discard" => io_service.discard = val,
            "Total" => io_service.total = val,
            _ => {}
        }
    }

    if io_service.major != 0 {
        io_services.push(io_service);
    }

    Ok(io_services)
}

fn parse_io_stat(s: String) -> Result<Vec<IoStat>> {
    let mut stats = Vec::new();

    for line in s.lines().filter(|line| !line.trim().is_empty()) {
        let mut fields = line.split_whitespace();
        let device = fields.next().ok_or_else(|| Error::new(ParseError))?;
        let (major, minor) = device
            .split_once(':')
            .ok_or_else(|| Error::new(ParseError))?;
        let mut stat = IoStat {
            major: major.parse::<i16>().map_err(|_| Error::new(ParseError))?,
            minor: minor.parse::<i16>().map_err(|_| Error::new(ParseError))?,
            rbytes: 0,
            wbytes: 0,
            rios: 0,
            wios: 0,
            dbytes: 0,
            dios: 0,
        };

        // io.stat is a nested-keyed file: counters can be omitted when zero,
        // their order is not significant, and future kernels may add keys.
        for field in fields {
            let (key, value) = field
                .split_once('=')
                .ok_or_else(|| Error::new(ParseError))?;
            let value = value.parse::<u64>().map_err(|_| Error::new(ParseError))?;

            match key {
                "rbytes" => stat.rbytes = value,
                "wbytes" => stat.wbytes = value,
                "rios" => stat.rios = value,
                "wios" => stat.wios = value,
                "dbytes" => stat.dbytes = value,
                "dios" => stat.dios = value,
                _ => {}
            }
        }

        stats.push(stat);
    }

    Ok(stats)
}

fn parse_io_service_total(s: String) -> Result<u64> {
    if s.trim().is_empty() {
        return Ok(0);
    }

    for line in s.lines() {
        let mut parts = line.split_whitespace();
        if parts.next() != Some("Total") {
            continue;
        }
        let value = parts.next().ok_or_else(|| Error::new(ParseError))?;
        if parts.next().is_some() {
            return Err(Error::new(ParseError));
        }
        return value.parse::<u64>().map_err(|_| Error::new(ParseError));
    }

    Err(Error::new(ParseError))
}

fn parse_blkio_data(s: String) -> Result<Vec<BlkIoData>> {
    let mut res = Vec::new();
    for line in s.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.is_empty() {
            continue;
        }
        if fields.len() != 2 {
            return Err(Error::new(ParseError));
        }
        let (major, minor) = fields[0]
            .split_once(':')
            .ok_or_else(|| Error::new(ParseError))?;
        res.push(BlkIoData {
            major: major.parse::<i16>().map_err(|_| Error::new(ParseError))?,
            minor: minor.parse::<i16>().map_err(|_| Error::new(ParseError))?,
            data: fields[1]
                .parse::<u64>()
                .map_err(|_| Error::new(ParseError))?,
        });
    }

    Ok(res)
}

/// Current state and statistics about how throttled are the block devices when accessed from the
/// controller's control group.
#[derive(Default, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BlkIoThrottle {
    /// Statistics about the bytes transferred between the block devices by the tasks in this
    /// control group.
    pub io_service_bytes: Vec<IoService>,
    /// Total amount of bytes transferred to and from the block devices.
    pub io_service_bytes_total: u64,
    /// Same as `io_service_bytes`, but contains all descendant control groups.
    pub io_service_bytes_recursive: Vec<IoService>,
    /// Total amount of bytes transferred to and from the block devices, including all descendant
    /// control groups.
    pub io_service_bytes_recursive_total: u64,
    /// The number of I/O operations performed on the devices as seen by the throttling policy.
    pub io_serviced: Vec<IoService>,
    /// The total number of I/O operations performed on the devices as seen by the throttling
    /// policy.
    pub io_serviced_total: u64,
    /// Same as `io_serviced`, but contains all descendant control groups.
    pub io_serviced_recursive: Vec<IoService>,
    /// Same as `io_serviced`, but contains all descendant control groups and contains only the
    /// total amount.
    pub io_serviced_recursive_total: u64,
    /// The upper limit of bytes per second rate of read operation on the block devices by the
    /// control group's tasks.
    pub read_bps_device: Vec<BlkIoData>,
    /// The upper limit of I/O operation per second, when said operation is a read operation.
    pub read_iops_device: Vec<BlkIoData>,
    /// The upper limit of bytes per second rate of write operation on the block devices by the
    /// control group's tasks.
    pub write_bps_device: Vec<BlkIoData>,
    /// The upper limit of I/O operation per second, when said operation is a write operation.
    pub write_iops_device: Vec<BlkIoData>,
}

/// Statistics and state of the block devices.
#[derive(Default, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct BlkIo {
    /// The number of BIOS requests merged into I/O requests by the control group's tasks.
    pub io_merged: Vec<IoService>,
    /// Same as `io_merged`, but only reports the total number.
    pub io_merged_total: u64,
    /// Same as `io_merged`, but contains all descendant control groups.
    pub io_merged_recursive: Vec<IoService>,
    /// Same as `io_merged_recursive`, but only reports the total number.
    pub io_merged_recursive_total: u64,
    /// The number of requests queued for I/O operations by the tasks of the control group.
    pub io_queued: Vec<IoService>,
    /// Same as `io_queued`, but only reports the total number.
    pub io_queued_total: u64,
    /// Same as `io_queued`, but contains all descendant control groups.
    pub io_queued_recursive: Vec<IoService>,
    /// Same as `io_queued_recursive`, but contains all descendant control groups.
    pub io_queued_recursive_total: u64,
    /// The number of bytes transferred from and to the block device (as seen by the CFQ I/O scheduler).
    pub io_service_bytes: Vec<IoService>,
    /// Same as `io_service_bytes`, but contains all descendant control groups.
    pub io_service_bytes_total: u64,
    /// Same as `io_service_bytes`, but contains all descendant control groups.
    pub io_service_bytes_recursive: Vec<IoService>,
    /// Total amount of bytes transferred between the tasks and block devices, including the
    /// descendant control groups' numbers.
    pub io_service_bytes_recursive_total: u64,
    /// The number of I/O operations (as seen by the CFQ I/O scheduler) between the devices and the
    /// control group's tasks.
    pub io_serviced: Vec<IoService>,
    /// The total number of I/O operations performed on the devices as seen by the throttling
    /// policy.
    pub io_serviced_total: u64,
    /// Same as `io_serviced`, but contains all descendant control groups.
    pub io_serviced_recursive: Vec<IoService>,
    /// Same as `io_serviced`, but contains all descendant control groups and contains only the
    /// total amount.
    pub io_serviced_recursive_total: u64,
    /// The total time spent between dispatch and request completion for I/O requests (as seen by
    /// the CFQ I/O scheduler) by the control group's tasks.
    pub io_service_time: Vec<IoService>,
    /// Same as `io_service_time`, but contains all descendant control groups and contains only the
    /// total amount.
    pub io_service_time_total: u64,
    /// Same as `io_service_time`, but contains all descendant control groups.
    pub io_service_time_recursive: Vec<IoService>,
    /// Same as `io_service_time_recursive`, but contains all descendant control groups and only
    /// the total amount.
    pub io_service_time_recursive_total: u64,
    /// Total amount of time spent waiting for a free slot in the CFQ I/O scheduler's queue.
    pub io_wait_time: Vec<IoService>,
    /// Same as `io_wait_time`, but only reports the total amount.
    pub io_wait_time_total: u64,
    /// Same as `io_wait_time`, but contains all descendant control groups.
    pub io_wait_time_recursive: Vec<IoService>,
    /// Same as `io_wait_time_recursive`, but only reports the total amount.
    pub io_wait_time_recursive_total: u64,
    /// How much weight do the control group's tasks have when competing against the descendant
    /// control group's tasks.
    pub leaf_weight: u64,
    /// Same as `leaf_weight`, but per-block-device.
    pub leaf_weight_device: Vec<BlkIoData>,
    /// Total number of sectors transferred between the block devices and the control group's
    /// tasks.
    pub sectors: Vec<BlkIoData>,
    /// Same as `sectors`, but contains all descendant control groups.
    pub sectors_recursive: Vec<BlkIoData>,
    /// Similar statistics, but as seen by the throttle policy.
    pub throttle: BlkIoThrottle,
    /// The time the control group had access to the I/O devices.
    pub time: Vec<BlkIoData>,
    /// Same as `time`, but contains all descendant control groups.
    pub time_recursive: Vec<BlkIoData>,
    /// The weight of this control group.
    pub weight: u64,
    /// Same as `weight`, but per-block-device.
    pub weight_device: Vec<BlkIoData>,

    /// IoStat for cgroup v2
    pub io_stat: Vec<IoStat>,
}

impl ControllerInternal for BlkIoController {
    fn control_type(&self) -> Controllers {
        Controllers::BlkIo
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
        let res: &BlkIoResources = &res.blkio;
        let mut tracker = UpdateTracker::new();

        tracker.step_opt("blkio.weight", res.weight, |weight| {
            self.set_weight(weight as u64)
        })?;
        tracker.step_opt("blkio.leaf_weight", res.leaf_weight, |leaf_weight| {
            self.set_leaf_weight(leaf_weight as u64)
        })?;

        for dev in &res.weight_device {
            if let Some(weight) = dev.weight {
                tracker.step(
                    &format!("blkio.weight_device:{}:{}", dev.major, dev.minor),
                    || self.set_weight_for_device(dev.major, dev.minor, weight as u64),
                )?;
            }
            if let Some(leaf_weight) = dev.leaf_weight {
                tracker.step(
                    &format!("blkio.leaf_weight_device:{}:{}", dev.major, dev.minor),
                    || self.set_leaf_weight_for_device(dev.major, dev.minor, leaf_weight as u64),
                )?;
            }
        }

        for dev in &res.throttle_read_bps_device {
            tracker.step(
                &format!("blkio.throttle.read_bps_device:{}:{}", dev.major, dev.minor),
                || self.throttle_read_bps_for_device(dev.major, dev.minor, dev.rate),
            )?;
        }

        for dev in &res.throttle_write_bps_device {
            tracker.step(
                &format!(
                    "blkio.throttle.write_bps_device:{}:{}",
                    dev.major, dev.minor
                ),
                || self.throttle_write_bps_for_device(dev.major, dev.minor, dev.rate),
            )?;
        }

        for dev in &res.throttle_read_iops_device {
            tracker.step(
                &format!(
                    "blkio.throttle.read_iops_device:{}:{}",
                    dev.major, dev.minor
                ),
                || self.throttle_read_iops_for_device(dev.major, dev.minor, dev.rate),
            )?;
        }

        for dev in &res.throttle_write_iops_device {
            tracker.step(
                &format!(
                    "blkio.throttle.write_iops_device:{}:{}",
                    dev.major, dev.minor
                ),
                || self.throttle_write_iops_for_device(dev.major, dev.minor, dev.rate),
            )?;
        }

        for (k, v) in &res.attrs {
            tracker.step(k, || self.set(k, v))?;
        }

        Ok(())
    }
}

impl ControllIdentifier for BlkIoController {
    fn controller_type() -> Controllers {
        Controllers::BlkIo
    }
}

impl<'a> From<&'a Subsystem> for &'a BlkIoController {
    fn from(sub: &'a Subsystem) -> &'a BlkIoController {
        unsafe {
            match sub {
                Subsystem::BlkIo(c) => c,
                _ => {
                    assert_eq!(1, 0);
                    let v = std::mem::MaybeUninit::uninit();
                    v.assume_init()
                }
            }
        }
    }
}

impl BlkIoController {
    /// Constructs a new `BlkIoController` with `root` serving as the root of the control group.
    pub fn new(point: PathBuf, root: PathBuf, v2: bool) -> Self {
        Self {
            base: root,
            path: point,
            v2,
        }
    }

    fn blkio_v2_from_stat(stat_str: String) -> BlkIo {
        BlkIo {
            io_stat: parse_io_stat(stat_str).unwrap_or_default(),
            ..Default::default()
        }
    }

    fn try_blkio_v2(&self) -> Result<BlkIo> {
        let stat_str = self
            .open_path("io.stat", false)
            .and_then(read_string_from)?;
        Ok(BlkIo {
            io_stat: parse_io_stat(stat_str)?,
            ..Default::default()
        })
    }

    /// Gathers statistics about and reports the state of the block devices used by the control
    /// group's tasks.
    #[deprecated(note = "use `try_blkio` instead")]
    pub fn blkio(&self) -> BlkIo {
        if self.v2 {
            let stat = self
                .open_path("io.stat", false)
                .and_then(read_string_from)
                .unwrap_or_default();
            return Self::blkio_v2_from_stat(stat);
        }

        let io_serviced = self
            .open_path("blkio.io_serviced", false)
            .and_then(read_string_from)
            .unwrap_or_default();
        let io_service_bytes = self
            .open_path("blkio.io_service_bytes", false)
            .and_then(read_string_from)
            .unwrap_or_default();
        self.blkio_v1_from_primary(io_serviced, io_service_bytes, false)
            .expect("best-effort blkio conversion cannot fail")
    }

    /// Gathers statistics about and reports the state of the block devices used by the control
    /// group's tasks, or an error if reading failed.
    pub fn try_blkio(&self) -> Result<BlkIo> {
        if self.v2 {
            return self.try_blkio_v2();
        }
        let io_serviced_str = self
            .open_path("blkio.io_serviced", false)
            .and_then(read_string_from)?;
        let io_service_bytes_str = self
            .open_path("blkio.io_service_bytes", false)
            .and_then(read_string_from)?;

        self.blkio_v1_from_primary(io_serviced_str, io_service_bytes_str, true)
    }

    fn blkio_v1_from_primary(
        &self,
        io_serviced_str: String,
        io_service_bytes_str: String,
        fallible: bool,
    ) -> Result<BlkIo> {
        macro_rules! stat {
            ($result:expr) => {{
                let result = $result;
                if fallible {
                    optional_read(result)?
                } else {
                    result.unwrap_or_default()
                }
            }};
        }

        Ok(BlkIo {
            io_merged: stat!(self
                .open_path("blkio.io_merged", false)
                .and_then(read_string_from)
                .and_then(parse_io_service)),
            io_merged_total: stat!(self
                .open_path("blkio.io_merged", false)
                .and_then(read_string_from)
                .and_then(parse_io_service_total)),
            io_merged_recursive: stat!(self
                .open_path("blkio.io_merged_recursive", false)
                .and_then(read_string_from)
                .and_then(parse_io_service)),
            io_merged_recursive_total: stat!(self
                .open_path("blkio.io_merged_recursive", false)
                .and_then(read_string_from)
                .and_then(parse_io_service_total)),
            io_queued: stat!(self
                .open_path("blkio.io_queued", false)
                .and_then(read_string_from)
                .and_then(parse_io_service)),
            io_queued_total: stat!(self
                .open_path("blkio.io_queued", false)
                .and_then(read_string_from)
                .and_then(parse_io_service_total)),
            io_queued_recursive: stat!(self
                .open_path("blkio.io_queued_recursive", false)
                .and_then(read_string_from)
                .and_then(parse_io_service)),
            io_queued_recursive_total: stat!(self
                .open_path("blkio.io_queued_recursive", false)
                .and_then(read_string_from)
                .and_then(parse_io_service_total)),
            io_service_bytes: stat!(parse_io_service(io_service_bytes_str.clone())),
            io_service_bytes_total: stat!(parse_io_service_total(io_service_bytes_str)),
            io_service_bytes_recursive: stat!(self
                .open_path("blkio.io_service_bytes_recursive", false)
                .and_then(read_string_from)
                .and_then(parse_io_service)),
            io_service_bytes_recursive_total: stat!(self
                .open_path("blkio.io_service_bytes_recursive", false)
                .and_then(read_string_from)
                .and_then(parse_io_service_total)),
            io_serviced: stat!(parse_io_service(io_serviced_str.clone())),
            io_serviced_total: stat!(parse_io_service_total(io_serviced_str)),
            io_serviced_recursive: stat!(self
                .open_path("blkio.io_serviced_recursive", false)
                .and_then(read_string_from)
                .and_then(parse_io_service)),
            io_serviced_recursive_total: stat!(self
                .open_path("blkio.io_serviced_recursive", false)
                .and_then(read_string_from)
                .and_then(parse_io_service_total)),
            io_service_time: stat!(self
                .open_path("blkio.io_service_time", false)
                .and_then(read_string_from)
                .and_then(parse_io_service)),
            io_service_time_total: stat!(self
                .open_path("blkio.io_service_time", false)
                .and_then(read_string_from)
                .and_then(parse_io_service_total)),
            io_service_time_recursive: stat!(self
                .open_path("blkio.io_service_time_recursive", false)
                .and_then(read_string_from)
                .and_then(parse_io_service)),
            io_service_time_recursive_total: stat!(self
                .open_path("blkio.io_service_time_recursive", false)
                .and_then(read_string_from)
                .and_then(parse_io_service_total)),
            io_wait_time: stat!(self
                .open_path("blkio.io_wait_time", false)
                .and_then(read_string_from)
                .and_then(parse_io_service)),
            io_wait_time_total: stat!(self
                .open_path("blkio.io_wait_time", false)
                .and_then(read_string_from)
                .and_then(parse_io_service_total)),
            io_wait_time_recursive: stat!(self
                .open_path("blkio.io_wait_time_recursive", false)
                .and_then(read_string_from)
                .and_then(parse_io_service)),
            io_wait_time_recursive_total: stat!(self
                .open_path("blkio.io_wait_time_recursive", false)
                .and_then(read_string_from)
                .and_then(parse_io_service_total)),
            leaf_weight: stat!(self
                .open_path("blkio.leaf_weight", false)
                .and_then(read_u64_from)),
            leaf_weight_device: stat!(self
                .open_path("blkio.leaf_weight_device", false)
                .and_then(read_string_from)
                .and_then(parse_blkio_data)),
            sectors: stat!(self
                .open_path("blkio.sectors", false)
                .and_then(read_string_from)
                .and_then(parse_blkio_data)),
            sectors_recursive: stat!(self
                .open_path("blkio.sectors_recursive", false)
                .and_then(read_string_from)
                .and_then(parse_blkio_data)),
            throttle: BlkIoThrottle {
                io_service_bytes: stat!(self
                    .open_path("blkio.throttle.io_service_bytes", false)
                    .and_then(read_string_from)
                    .and_then(parse_io_service)),
                io_service_bytes_total: stat!(self
                    .open_path("blkio.throttle.io_service_bytes", false)
                    .and_then(read_string_from)
                    .and_then(parse_io_service_total)),
                io_service_bytes_recursive: stat!(self
                    .open_path("blkio.throttle.io_service_bytes_recursive", false)
                    .and_then(read_string_from)
                    .and_then(parse_io_service)),
                io_service_bytes_recursive_total: stat!(self
                    .open_path("blkio.throttle.io_service_bytes_recursive", false)
                    .and_then(read_string_from)
                    .and_then(parse_io_service_total)),
                io_serviced: stat!(self
                    .open_path("blkio.throttle.io_serviced", false)
                    .and_then(read_string_from)
                    .and_then(parse_io_service)),
                io_serviced_total: stat!(self
                    .open_path("blkio.throttle.io_serviced", false)
                    .and_then(read_string_from)
                    .and_then(parse_io_service_total)),
                io_serviced_recursive: stat!(self
                    .open_path("blkio.throttle.io_serviced_recursive", false)
                    .and_then(read_string_from)
                    .and_then(parse_io_service)),
                io_serviced_recursive_total: stat!(self
                    .open_path("blkio.throttle.io_serviced_recursive", false)
                    .and_then(read_string_from)
                    .and_then(parse_io_service_total)),
                read_bps_device: stat!(self
                    .open_path("blkio.throttle.read_bps_device", false)
                    .and_then(read_string_from)
                    .and_then(parse_blkio_data)),
                read_iops_device: stat!(self
                    .open_path("blkio.throttle.read_iops_device", false)
                    .and_then(read_string_from)
                    .and_then(parse_blkio_data)),
                write_bps_device: stat!(self
                    .open_path("blkio.throttle.write_bps_device", false)
                    .and_then(read_string_from)
                    .and_then(parse_blkio_data)),
                write_iops_device: stat!(self
                    .open_path("blkio.throttle.write_iops_device", false)
                    .and_then(read_string_from)
                    .and_then(parse_blkio_data)),
            },
            time: stat!(self
                .open_path("blkio.time", false)
                .and_then(read_string_from)
                .and_then(parse_blkio_data)),
            time_recursive: stat!(self
                .open_path("blkio.time_recursive", false)
                .and_then(read_string_from)
                .and_then(parse_blkio_data)),
            weight: stat!(self
                .open_path("blkio.weight", false)
                .and_then(read_u64_from)),
            weight_device: stat!(self
                .open_path("blkio.weight_device", false)
                .and_then(read_string_from)
                .and_then(parse_blkio_data)),
            io_stat: Vec::new(),
        })
    }

    /// Set the leaf weight on the control group's tasks, i.e., how are they weighted against the
    /// descendant control groups' tasks.
    pub fn set_leaf_weight(&self, w: u64) -> Result<()> {
        self.open_path("blkio.leaf_weight", true)
            .and_then(|mut file| {
                file.write_all(w.to_string().as_ref()).map_err(|e| {
                    Error::with_cause(
                        WriteFailed("blkio.leaf_weight".to_string(), w.to_string()),
                        e,
                    )
                })
            })
    }

    /// Same as `set_leaf_weight()`, but settable per each block device.
    pub fn set_leaf_weight_for_device(&self, major: u64, minor: u64, weight: u64) -> Result<()> {
        self.open_path("blkio.leaf_weight_device", true)
            .and_then(|mut file| {
                file.write_all(format!("{}:{} {}", major, minor, weight).as_ref())
                    .map_err(|e| {
                        Error::with_cause(
                            WriteFailed(
                                "blkio.leaf_weight_device".to_string(),
                                format!("{}:{} {}", major, minor, weight),
                            ),
                            e,
                        )
                    })
            })
    }

    /// Reset the statistics the kernel has gathered so far and start fresh.
    pub fn reset_stats(&self) -> Result<()> {
        self.open_path("blkio.reset_stats", true)
            .and_then(|mut file| {
                file.write_all("1".to_string().as_ref()).map_err(|e| {
                    Error::with_cause(
                        WriteFailed("blkio.reset_stats".to_string(), "1".to_string()),
                        e,
                    )
                })
            })
    }

    /// Throttle the bytes per second rate of read operation affecting the block device
    /// `major:minor` to `bps`.
    pub fn throttle_read_bps_for_device(&self, major: u64, minor: u64, bps: u64) -> Result<()> {
        let mut file_name = "blkio.throttle.read_bps_device";
        let mut content = format!("{}:{} {}", major, minor, bps);
        if self.v2 {
            file_name = "io.max";
            content = format!("{}:{} rbps={}", major, minor, bps);
        }
        self.open_path(file_name, true).and_then(|mut file| {
            file.write_all(content.as_ref()).map_err(|e| {
                Error::with_cause(WriteFailed(file_name.to_string(), content.to_string()), e)
            })
        })
    }

    /// Throttle the I/O operations per second rate of read operation affecting the block device
    /// `major:minor` to `bps`.
    pub fn throttle_read_iops_for_device(&self, major: u64, minor: u64, iops: u64) -> Result<()> {
        let mut file_name = "blkio.throttle.read_iops_device";
        let mut content = format!("{}:{} {}", major, minor, iops);
        if self.v2 {
            file_name = "io.max";
            content = format!("{}:{} riops={}", major, minor, iops);
        }
        self.open_path(file_name, true).and_then(|mut file| {
            file.write_all(content.as_ref()).map_err(|e| {
                Error::with_cause(WriteFailed(file_name.to_string(), content.to_string()), e)
            })
        })
    }
    /// Throttle the bytes per second rate of write operation affecting the block device
    /// `major:minor` to `bps`.
    pub fn throttle_write_bps_for_device(&self, major: u64, minor: u64, bps: u64) -> Result<()> {
        let mut file_name = "blkio.throttle.write_bps_device";
        let mut content = format!("{}:{} {}", major, minor, bps);
        if self.v2 {
            file_name = "io.max";
            content = format!("{}:{} wbps={}", major, minor, bps);
        }
        self.open_path(file_name, true).and_then(|mut file| {
            file.write_all(content.as_ref()).map_err(|e| {
                Error::with_cause(WriteFailed(file_name.to_string(), content.to_string()), e)
            })
        })
    }

    /// Throttle the I/O operations per second rate of write operation affecting the block device
    /// `major:minor` to `bps`.
    pub fn throttle_write_iops_for_device(&self, major: u64, minor: u64, iops: u64) -> Result<()> {
        let mut file_name = "blkio.throttle.write_iops_device";
        let mut content = format!("{}:{} {}", major, minor, iops);
        if self.v2 {
            file_name = "io.max";
            content = format!("{}:{} wiops={}", major, minor, iops);
        }
        self.open_path(file_name, true).and_then(|mut file| {
            file.write_all(content.as_ref()).map_err(|e| {
                Error::with_cause(WriteFailed(file_name.to_string(), content.to_string()), e)
            })
        })
    }

    /// Set the weight of the control group's tasks.
    pub fn set_weight(&self, w: u64) -> Result<()> {
        // Attation: may not find in high kernel version.
        let mut file_name = "blkio.weight";
        if self.v2 {
            file_name = "io.bfq.weight";
        }
        self.open_path(file_name, true).and_then(|mut file| {
            file.write_all(w.to_string().as_ref()).map_err(|e| {
                Error::with_cause(WriteFailed(file_name.to_string(), w.to_string()), e)
            })
        })
    }

    /// Same as `set_weight()`, but settable per each block device.
    pub fn set_weight_for_device(&self, major: u64, minor: u64, weight: u64) -> Result<()> {
        let mut file_name = "blkio.weight_device";
        if self.v2 {
            // Attation: there is no weight for device in runc
            // https://github.com/opencontainers/runc/blob/46be7b612e2533c494e6a251111de46d8e286ed5/libcontainer/cgroups/fs2/io.go#L30
            // may depends on IO schedulers https://wiki.ubuntu.com/Kernel/Reference/IOSchedulers
            file_name = "io.bfq.weight";
        }
        self.open_path(file_name, true).and_then(|mut file| {
            file.write_all(format!("{}:{} {}", major, minor, weight).as_ref())
                .map_err(|e| {
                    Error::with_cause(
                        WriteFailed(
                            file_name.to_string(),
                            format!("{}:{} {}", major, minor, weight),
                        ),
                        e,
                    )
                })
        })
    }
}

impl CustomizedAttribute for BlkIoController {}
#[cfg(test)]
mod test {
    use crate::fs::blkio::{parse_blkio_data, BlkIoController, BlkIoData};
    use crate::fs::blkio::{parse_io_service, parse_io_service_total, parse_io_stat, IoService};
    use crate::fs::error::*;
    use std::fs;

    static TEST_VALUE: &str = "\
8:32 Read 4280320
8:32 Write 0
8:32 Sync 4280320
8:32 Async 0
8:32 Discard 1
8:32 Total 4280320
8:48 Read 5705479168
8:48 Write 56096055296
8:48 Sync 11213923328
8:48 Async 50587611136
8:48 Total 61801534464
8:16 Read 10059776
8:16 Write 0
8:16 Sync 10059776
8:16 Async 0
8:16 Total 10059776
8:0 Read 7192576
8:0 Write 0
8:0 Sync 7192576
8:0 Async 0
8:0 Total 7192576
Total 61823067136
 ";

    static TEST_BLKIO_DATA: &str = "\
8:48 454480833999
8:32 228392923193
8:16 772456885
8:0 559583764
 ";

    #[test]
    fn test_parse_io_service_total() {
        let ok = parse_io_service_total(TEST_VALUE.to_string()).unwrap();
        assert_eq!(ok, 61823067136);
        assert_eq!(parse_io_service_total(String::new()).unwrap(), 0);
        assert_eq!(
            parse_io_service_total("Total invalid\n".to_string())
                .unwrap_err()
                .kind(),
            &ErrorKind::ParseError
        );
    }

    #[test]
    fn test_parse_io_service() {
        let ok = parse_io_service(TEST_VALUE.to_string()).unwrap();
        assert_eq!(
            ok,
            vec![
                IoService {
                    major: 8,
                    minor: 32,
                    read: 4280320,
                    write: 0,
                    sync: 4280320,
                    r#async: 0,
                    discard: 1,
                    total: 4280320,
                },
                IoService {
                    major: 8,
                    minor: 48,
                    read: 5705479168,
                    write: 56096055296,
                    sync: 11213923328,
                    r#async: 50587611136,
                    discard: 0,
                    total: 61801534464,
                },
                IoService {
                    major: 8,
                    minor: 16,
                    read: 10059776,
                    write: 0,
                    sync: 10059776,
                    r#async: 0,
                    discard: 0,
                    total: 10059776,
                },
                IoService {
                    major: 8,
                    minor: 0,
                    read: 7192576,
                    write: 0,
                    sync: 7192576,
                    r#async: 0,
                    discard: 0,
                    total: 7192576,
                }
            ]
        );

        let invalid_values = vec![
            "\
8:32 Read 4280320
8:32 Write a
8:32 Async 1
",
            "\
8:32 Read 4280320
b:32 Write 1
8:32 Async 1
",
            "\
8:32 Read 4280320
8:32 Write 1
8:c Async 1
",
        ];

        for value in invalid_values {
            let err = parse_io_service(value.to_string()).unwrap_err();
            assert_eq!(err.kind(), &ErrorKind::ParseError,);
        }
    }

    #[test]
    fn test_parse_blkio_data() {
        assert_eq!(
            parse_blkio_data(TEST_BLKIO_DATA.to_string()).unwrap(),
            vec![
                BlkIoData {
                    major: 8,
                    minor: 48,
                    data: 454480833999,
                },
                BlkIoData {
                    major: 8,
                    minor: 32,
                    data: 228392923193,
                },
                BlkIoData {
                    major: 8,
                    minor: 16,
                    data: 772456885,
                },
                BlkIoData {
                    major: 8,
                    minor: 0,
                    data: 559583764,
                }
            ]
        );
        assert_eq!(
            parse_blkio_data("8:not-a-minor 1\n".to_string())
                .unwrap_err()
                .kind(),
            &ErrorKind::ParseError
        );
    }

    #[test]
    fn test_parse_io_stat_accepts_keyed_partial_device_lines() {
        let input = concat!(
            "8:0 dios=6 rbytes=1 unknown=7 wios=4 rios=3 dbytes=5 wbytes=2\n",
            "7:7 \n",
            "8:1 wbytes=9\n",
        );

        assert_eq!(
            parse_io_stat(input.to_string()).unwrap(),
            vec![
                crate::fs::blkio::IoStat {
                    major: 8,
                    minor: 0,
                    rbytes: 1,
                    wbytes: 2,
                    rios: 3,
                    wios: 4,
                    dbytes: 5,
                    dios: 6,
                },
                crate::fs::blkio::IoStat {
                    major: 7,
                    minor: 7,
                    rbytes: 0,
                    wbytes: 0,
                    rios: 0,
                    wios: 0,
                    dbytes: 0,
                    dios: 0,
                },
                crate::fs::blkio::IoStat {
                    major: 8,
                    minor: 1,
                    rbytes: 0,
                    wbytes: 9,
                    rios: 0,
                    wios: 0,
                    dbytes: 0,
                    dios: 0,
                },
            ]
        );

        assert_eq!(
            BlkIoController::blkio_v2_from_stat(input.to_string())
                .io_stat
                .len(),
            3
        );
    }

    #[test]
    fn test_parse_io_stat_reports_malformed_values() {
        let valid = "8:0 rbytes=1 wbytes=2 rios=3 wios=4 dbytes=5 dios=6\n";
        assert_eq!(
            parse_io_stat(valid.replace("rbytes=1", "rbytes=invalid"))
                .unwrap_err()
                .kind(),
            &ErrorKind::ParseError
        );
        assert_eq!(
            parse_io_stat("8:0 rbytes\n".to_string())
                .unwrap_err()
                .kind(),
            &ErrorKind::ParseError
        );
    }

    #[test]
    fn test_try_blkio_defaults_only_missing_optional_files() {
        let path = std::env::temp_dir().join(format!(
            "cgroups-blkio-try-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        fs::create_dir_all(&path).unwrap();
        fs::write(path.join("blkio.io_serviced"), TEST_VALUE).unwrap();
        fs::write(path.join("blkio.io_service_bytes"), TEST_VALUE).unwrap();
        let controller = BlkIoController::new(path.clone(), path.clone(), false);

        let stats = controller.try_blkio().unwrap();
        assert_eq!(stats.io_serviced_total, 61823067136);
        assert_eq!(stats.weight, 0);

        fs::write(path.join("blkio.weight"), "invalid\n").unwrap();
        assert_eq!(
            controller.try_blkio().unwrap_err().kind(),
            &ErrorKind::ParseError
        );

        fs::remove_dir_all(path).unwrap();
    }
}
