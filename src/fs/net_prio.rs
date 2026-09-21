// Copyright (c) 2018 Levente Kurusa
//
// SPDX-License-Identifier: Apache-2.0 or MIT
//

//! This module contains the implementation of the `net_prio` cgroup subsystem.
//!
//! See the Kernel's documentation for more information about this subsystem, found at:
//!  [Documentation/cgroup-v1/net_prio.txt](https://www.kernel.org/doc/Documentation/cgroup-v1/net_prio.txt)
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

use crate::fs::error::ErrorKind::*;
use crate::fs::error::*;

use crate::fs::read_u64_from;
use crate::fs::{
    ControllIdentifier, ControllerInternal, Controllers, NetworkResources, Resources, Subsystem,
    UpdateTracker,
};

/// A controller that allows controlling the `net_prio` subsystem of a Cgroup.
///
/// In essence, using `net_prio` one can set the priority of the packets emitted from the control
/// group's tasks. This can then be used to have QoS restrictions on certain control groups and
/// tasks.
#[derive(Debug, Clone)]
pub struct NetPrioController {
    base: PathBuf,
    path: PathBuf,
}

impl ControllerInternal for NetPrioController {
    fn control_type(&self) -> Controllers {
        Controllers::NetPrio
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

    fn apply(&self, res: &Resources) -> Result<()> {
        // get the resources that apply to this controller
        let res: &NetworkResources = &res.network;
        let mut tracker = UpdateTracker::new();

        for i in &res.priorities {
            tracker.step(&format!("net_prio.ifpriomap:{}", i.name), || {
                self.set_if_prio(&i.name, i.priority)
            })?;
        }

        Ok(())
    }
}

impl ControllIdentifier for NetPrioController {
    fn controller_type() -> Controllers {
        Controllers::NetPrio
    }
}

impl<'a> From<&'a Subsystem> for &'a NetPrioController {
    fn from(sub: &'a Subsystem) -> &'a NetPrioController {
        unsafe {
            match sub {
                Subsystem::NetPrio(c) => c,
                _ => {
                    assert_eq!(1, 0);
                    let v = std::mem::MaybeUninit::uninit();
                    v.assume_init()
                }
            }
        }
    }
}

impl NetPrioController {
    /// Constructs a new `NetPrioController` with `root` serving as the root of the control group.
    pub fn new(point: PathBuf, root: PathBuf) -> Self {
        Self {
            base: root,
            path: point,
        }
    }

    /// Retrieves the current priority of the emitted packets.
    #[deprecated(note = "use `try_prio_idx` instead")]
    pub fn prio_idx(&self) -> u64 {
        self.open_path("net_prio.prioidx", false)
            .and_then(read_u64_from)
            .unwrap_or(0)
    }

    /// Retrieves the current priority of the emitted packets, or an error if reading failed.
    pub fn try_prio_idx(&self) -> Result<u64> {
        self.open_path("net_prio.prioidx", false)
            .and_then(read_u64_from)
    }

    /// A map of priorities for each network interface.
    pub fn ifpriomap(&self) -> Result<HashMap<String, u64>> {
        self.open_path("net_prio.ifpriomap", false)
            .and_then(|file| {
                let bf = BufReader::new(file);
                bf.lines()
                    .map(|line| {
                        let line = line.map_err(|_| Error::new(ParseError))?;
                        let mut parts = line.split_whitespace();

                        let ifname = parts.next().ok_or(Error::new(ParseError))?;
                        let ifprio_str = parts.next().ok_or(Error::new(ParseError))?;

                        let ifprio = ifprio_str
                            .trim()
                            .parse()
                            .map_err(|e| Error::with_cause(ParseError, e))?;

                        Ok((ifname.to_string(), ifprio))
                    })
                    .collect::<Result<HashMap<String, _>>>()
            })
    }

    /// Set the priority of the network traffic on `eif` to be `prio`.
    pub fn set_if_prio(&self, eif: &str, prio: u64) -> Result<()> {
        self.open_path("net_prio.ifpriomap", true)
            .and_then(|mut file| {
                file.write_all(format!("{} {}", eif, prio).as_ref())
                    .map_err(|e| {
                        Error::with_cause(
                            WriteFailed(
                                "net_prio.ifpriomap".to_string(),
                                format!("{} {}", eif, prio),
                            ),
                            e,
                        )
                    })
            })
    }
}
