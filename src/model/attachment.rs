// Copyright (c) 2026 Ant Group
// Copyright (c) 2026 Kata Contributors
//
// SPDX-License-Identifier: Apache-2.0 or MIT

//! Process and thread attachment destinations within a cgroup hierarchy.

use std::path::Path;

use crate::error::{CoreError, CoreResult, PathReason};
use crate::model::path::CgroupPath;
use crate::model::pid::ProcessId;

/// Destination for process or thread attachment within a cgroup hierarchy.
///
/// In cgroup v2, a domain cgroup that has enabled controllers in its
/// `cgroup.subtree_control` cannot contain any processes directly (the
/// "no internal processes" constraint). To avoid `EBUSY` when running
/// nested containers or supervisors, processes must be attached to a leaf
/// subgroup (e.g. `init`, `init.scope`, `payload`).
///
/// `AttachDestination` makes this placement an explicit caller choice
/// rather than relying on container-runtime heuristics (such as checking
/// whether an `init` directory happens to exist).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum AttachDestination {
    /// Attach directly to the managed cgroup root.
    #[default]
    ManagedCgroup,
    /// Attach to a validated descendant subgroup of the managed cgroup.
    Subgroup(CgroupPath),
    /// Resolve the reference process's current cgroup membership at
    /// attach time and attach there (verifying it is inside the managed
    /// cgroup subtree).
    SameCgroupAs(ProcessId),
}

impl AttachDestination {
    /// Construct a subgroup attachment destination, validating the path as a
    /// [`CgroupPath`].
    ///
    /// Root paths (empty, `/`, or `.`) are explicitly rejected: targeting the
    /// managed root must be expressed via [`AttachDestination::ManagedCgroup`].
    pub fn subgroup<P: AsRef<Path>>(path: P) -> CoreResult<Self> {
        let cpath = CgroupPath::new(path)?;
        if cpath.is_root() {
            return Err(CoreError::InvalidPath {
                input: cpath.as_path().to_path_buf(),
                reason: PathReason::Root,
                operation: "AttachDestination::subgroup",
            });
        }
        Ok(Self::Subgroup(cpath))
    }

    /// Construct a reference-process destination from a validated [`ProcessId`].
    pub fn same_cgroup_as(pid: ProcessId) -> Self {
        Self::SameCgroupAs(pid)
    }

    /// Returns `true` if this destination targets the managed cgroup root.
    pub fn is_managed_cgroup(&self) -> bool {
        matches!(self, Self::ManagedCgroup)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_is_managed_cgroup() {
        assert_eq!(
            AttachDestination::default(),
            AttachDestination::ManagedCgroup
        );
        assert!(AttachDestination::default().is_managed_cgroup());
    }

    #[test]
    fn test_subgroup_construction() {
        let dest = AttachDestination::subgroup("init").unwrap();
        assert_eq!(
            dest,
            AttachDestination::Subgroup(CgroupPath::new("init").unwrap())
        );
        assert!(!dest.is_managed_cgroup());

        // Invalid path (absolute, escaping, or root) must fail
        assert!(AttachDestination::subgroup("/init").is_err());
        assert!(AttachDestination::subgroup("../escape").is_err());
        assert!(AttachDestination::subgroup("").is_err());
        assert!(AttachDestination::subgroup("/").is_err());
        assert!(AttachDestination::subgroup(".").is_err());
    }

    #[test]
    fn test_same_cgroup_as_construction() {
        let pid = ProcessId::new(1234).unwrap();
        let dest = AttachDestination::same_cgroup_as(pid);
        assert_eq!(dest, AttachDestination::SameCgroupAs(pid));
        assert!(!dest.is_managed_cgroup());
    }
}
