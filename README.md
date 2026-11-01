# cgroups-rs

[![Crate](https://img.shields.io/crates/v/cgroups-rs.svg)](https://crates.io/crates/cgroups-rs)

Native Rust library for managing Linux control groups. Supports both cgroups v1 and v2.

## Examples

### Create a control group using the builder pattern

```rust,no_run
use cgroups_rs::*;
use cgroups_rs::core::CgroupPath;
use cgroups_rs::fs::*;

// Acquire a handle for the cgroup hierarchy.
let hier = cgroups_rs::fs::hierarchies::auto().expect("failed to discover cgroup hierarchy");

// Create a cgroup on the discovered hierarchy, managing its CPU controller.
let cg = Cgroup::builder(hier, CgroupPath::new("example").unwrap())
    .controllers(ControllerSelection::Only(vec!["cpu".to_string()]))
    .create()
    .expect("failed to create cgroup");

// Resource configuration is separate from handle construction.
let mut resources = Resources::default();
resources.cpu.shares = Some(85);
cg.apply(&resources).expect("failed to apply resources");

// CPU shares are a relative weight against siblings, not a percentage.

// Get a handle to the CPU controller.
let cpus: &cgroups_rs::fs::cpu::CpuController = cg.controller_of().unwrap();
cpus.add_task(&CgroupPid::from(1234u64));

// [...]

// Finally, clean up and delete the control group.
cg.delete();

// Note that `Cgroup` does not implement `Drop` and therefore when the
// structure is dropped, the Cgroup will stay around. This is because, later
// you can then re-create the `Cgroup` using `load()`. We aren't too set on
// this behavior, so it might change in the feature. Rest assured, it will be a
// major version change.
```

## Breaking changes for 1.0

- On cgroup v2, `MemController::set_swappiness()` and `Controller::apply()` /
  `Cgroup::apply()` with `Resources.memory.swappiness = Some(...)` now return
  `ErrorKind::CgroupVersion`. In 0.5.1 these requests wrote the swappiness value
  into `memory.swap.max`, changing the swap byte limit. Leave swappiness as
  `None` on v2; set swap limits with `set_memswap_limit()` or
  `Resources.memory.memory_swap_limit` instead.

- `Controller` and `Cgroup` membership readers (`tasks()` / `procs()`),
  `CpuSetController::cpuset()`, and `CpuAcctController::cpuacct()` now return
  `fs::error::Result<T>` instead of bare values. Propagate I/O and parse errors
  with `?` or handle them explicitly. Custom `Controller` implementations must
  update both membership signatures and propagate failures.
  `cpuset()` / `cpuacct()` attach `ReadFileError` with the full path and original
  I/O or parser error as its source.
  OCI `FsManager::pids()` / `SystemdManager::pids()` now propagate membership-read
  failures, but still return an empty list when the corresponding cgroup
  directory is confirmed absent. `FsManager::destroy()` tolerates absent cgroups
  and v2 threaded `cgroup.procs` reads returning `EOPNOTSUPP`; other membership
  read failures propagate and removal enforces emptiness.
  `stats()` remains best effort and omits CPU accounting on required-read failure.
- `CpuSet::sched_relax_domain_level` changed from `u64` in 0.5.1 to
  `Option<i64>`. Handle `None` for an unavailable interface and preserve
  `Some(-1)` as the system-default request.
- `Cgroup::apply()` and `CpuSetController::apply()` now propagate cpuset write
  failures ignored in 0.5.1. Updates are not rolled back; earlier writes may
  have taken effect.
- Resource write errors use controller file names and serialized values;
  open failures previously reported a full path and placeholder. Update
  `WriteFailed` matches and downcast the immediate source to
  `fs::error::WriteFileError` for the full path and original I/O error.
- `fs::error::ErrorKind` is now `#[non_exhaustive]`; add a wildcard arm
  (`_ => ...`) to downstream matches so future variants do not break them.
- `Cgroup::new` and `Cgroup::load` now take `Arc<dyn Hierarchy>` and a
  validated `CgroupPath`, replacing `Box<dyn Hierarchy>` and `AsRef<Path>`.
  Wrap custom hierarchies with `Arc::new(...)` (or convert an existing `Box`
  with `Arc::from(...)`), and clone the `Arc` to reuse it across handles.
  Validate relative paths with `CgroupPath::new(...)`; use `CgroupPath::root()`
  for the hierarchy root. Validation returns `PathError` with the original
  input and operation, and non-UTF-8 path bytes are preserved.
- Replaced `fs::cgroup_builder::CgroupBuilder`, including its resource chain,
  `set_specified_controllers(...)`, and `build(hier)`, with `fs::CgroupBuilder`
  returned by `Cgroup::builder(hier, path)`. Select controllers with
  `controllers(ControllerSelection::{All, Only(...)})`, then finish with
  `try_load()?` to validate controller names, `load()` to filter unavailable
  names, or `create()?` to create the cgroup. Configure the public `Resources`
  fields and call `cg.apply(&resources)?` separately, as in the example above.
- Removed `Cgroup::new_with_specified_controllers`,
  `load_with_specified_controllers`, `new_with_relative_paths`, and
  `load_with_relative_paths`. Use the builder's `controllers(...)` and
  `v1_prefixes(...)`; v1 prefixes now use `HashMap<String, CgroupPath>`
  instead of `HashMap<String, String>`. Prefixes also apply to handles at an
  empty relative path and bound `parent()` traversal there. On v1 each
  controller directory is `<mount>/<prefix>/<path>`; on v2 prefixes are ignored
  and the directory is `<unified mount>/<path>`. Use prefixes for existing v1
  membership and `path` for cgroups the caller creates. The caller chooses this
  split; it cannot be inferred from the directory. `CgroupReader::memberships`
  returns raw procfs strings, including leading `/`, possible namespace-relative
  `..`, and v2/named-hierarchy entries. Select matching controller keys and map
  the observations relative to the visible mounts before validating them as
  prefixes; these raw strings are not builder inputs.
- Renamed `fs::cgroup::get_cgroups_relative_paths()` and
  `get_cgroups_relative_paths_by_pid(pid)` to `get_cgroup_memberships()` and
  `get_cgroup_memberships_by_pid(pid)`. Both return the same raw procfs strings
  as `CgroupReader::default().memberships(None)` or `.memberships(Some(pid))`.
- `Cgroup::path()` now returns `&CgroupPath` instead of `&str`. Use
  `cg.path().as_path()` for a `&Path`, or pass `cg.path()` directly to an API
  accepting `AsRef<Path>`. Call `cg.path().as_path().to_str()` explicitly when
  UTF-8 is required. The returned path excludes per-controller v1 prefixes.
  `Cgroup::subsystems()` now returns `&[Subsystem]` instead of `&Vec<Subsystem>`.
- Replaced `Cgroup::parent_control_group() -> Cgroup` with
  `parent() -> Result<Cgroup>`. Parent handles preserve controller selection
  and v1 prefixes, and a handle at the relative root boundary returns an error
  with `PathError::RootPath` as its source. `move_task_to_parent*` propagates
  that error instead of falling back to the hierarchy root.
- Removed `Hierarchy::root_control_group` and `Hierarchy::parent_control_group`;
  remove these methods from custom implementations. Load root handles with
  `Cgroup::load(hierarchy.clone(), CgroupPath::root())` and derive parents with
  `cg.parent()?`. Cloning a handle preserves its hierarchy, controller
  selection, and v1 prefixes instead of rediscovering the host. `remove_task*`
  retains controller selection and returns to each v1 prefix directory (the
  hierarchy root if unset), or the unified root on v2. `set_release_agent`
  retains controller selection and ignores prefixes, targeting each v1
  hierarchy's true root.
- `Hierarchy::root()` now returns `fs::error::Result<PathBuf>` and represents only
  the unified mount point on v2. V1 implementations return
  `ErrorKind::CgroupVersion`; use the individual controllers' mount points
  (`V1::get_mount_point(...)` for a built-in v1 view). Update custom hierarchy
  implementations to this signature. `UnsupportedController.path` is now
  `Option<PathBuf>`: v2 reports its controller-list file as `Some(path)`, while
  v1 name validation reports `None` instead of an inferred hierarchy root.
- `hierarchies::auto()` now returns `CoreResult<Arc<dyn Hierarchy>>`; use
  `hierarchies::auto()?`. Removed `V1::new()`, `V1::try_new()`, `V2::new()`,
  and `Default` for `V1`, `V2`, and `Cgroup`. Use
  `V1::from(discover(&paths)?)` or the checked
  `V2::try_from(discover(&paths)?)`, then wrap the view in an `Arc` and load a
  handle at an explicit path. Built-in hierarchies always retain a validated
  topology snapshot. The checked v2 conversion rejects v1-primary and hybrid
  topologies.
- Discovery no longer falls back to a partial hierarchy after required read,
  parse, or layout failures, including empty `/proc/self/cgroup`, malformed
  mountinfo, and missing `cgroup.controllers` on v2-primary hosts. These return
  `CoreError` with source paths and original causes.
- Removed the legacy `Mountinfo` / `MountinfoError` types and
  `mountinfo_self()` / `try_mountinfo_self()` readers. Use `MountRecord` and
  the strict parsers in `core::discovery`, or read mounts from a discovered
  topology. The fallible `V1::try_new()`, `MountinfoError`, and
  `try_mountinfo_self()` APIs introduced during the discovery migration are
  superseded by `discover(...)` and `CoreError`; they were not in the `v0.5.1`
  release. `is_cgroup2_unified_mode()` now returns `CoreResult` so
  hierarchy-discovery failures remain diagnosable.
- `PropertiesBuilder::build()` now requires the primary `CgroupVersion` and
  returns `Vec<Property<'static>>` without discovery or other I/O. Pass
  `topology.version()`; hybrid hosts use `CgroupVersion::V1` and
  `BlockIOAccounting`, while unified v2 uses `IOAccounting`.
- `ControllerSelection::All` is the default. Creation rejects `Only(vec![])`
  with `EmptyControllerSelection` and rejects unavailable names with
  `UnsupportedController { controller, path }`, replacing
  `SpecifiedControllers`. `try_load()` rejects names absent from the hierarchy's
  reported subsystems; name validation adds no filesystem I/O. `load()` still
  silently filters them. Neither checks target existence or live availability, and
  both allow an empty selection when loading.
- On v2, select `io` for block I/O; `freezer` selects a core interface and is
  never written to `cgroup.subtree_control`. Selection restricts what the handle
  manages without disabling other kernel-enabled controllers.
- V2 creation reads each ancestor's `cgroup.subtree_control` and skips
  already-enabled controllers. `All` tries the discovered controllers offered
  by each directory's current `cgroup.controllers` one by one and ignores
  individual enabling write errors. This lets delegated callers traverse
  ancestors that offer controllers they cannot enable. `Only` requires its
  selected resource controllers to be available through the target directory
  and propagates enabling write errors, including missing permissions and
  kernel hierarchy constraints. Controller-state read errors and directory
  creation errors propagate for both selections. Creation and resource
  application do not roll back earlier changes when a later operation fails.
- With the `oci` feature, manager construction now requires explicit dependencies:
  `FsManager::new(topology: Arc<CgroupTopology>, base: CgroupPath)` and
  `SystemdManager::new(topology: Arc<CgroupTopology>, path: &str)`, both returning
  `oci::Result<Self>`. Call `discover(&HostPaths::default())?` once and pass
  clones of the returned `Arc` to share the topology. The `with_host_paths` and
  `with_topology` constructor variants have been removed. For `FsManager`, use
  `CgroupPath::new(base)?` or `CgroupPath::root()`; absolute bases and paths
  containing `..` are rejected during path construction. `SystemdManager` keeps
  the `"slice:prefix:name"` string format.
- `Manager::paths()` is replaced by `memberships() -> &CgroupMembership`,
  borrowing the discovery snapshot's records with their hierarchy IDs,
  controller groups, and original path bytes. Leading `/`, namespace-relative
  `..`, and non-UTF-8 names remain observations, not validated `CgroupPath`
  values. The snapshot does not update after process migration.
  `Manager::mounts()` now returns an owned `HashMap<String, PathBuf>`, computed
  on demand from the same topology without I/O. It maps observed v1 controllers;
  a pure unified-v2 topology returns an empty map. Manager construction no
  longer builds string maps or rejects valid non-UTF-8 observations. The
  `LegacyPathNotUtf8` and `LegacyMountPointNotUtf8` parser errors are removed.
- `Manager::cgroup_path()` now returns `oci::Result<PathBuf>` and preserves
  path bytes. Its existing coordinates remain distinct: v1 returns the selected
  controller's process membership from the discovery snapshot; v2 returns the
  discovered unified mount joined with the managed base, correcting the
  hard-coded `/sys/fs/cgroup` prefix used in 0.5.1.
- `FsManager::subcgroup()` now returns `oci::Result<&str>` so v2 root lookup
  errors propagate; use `manager.subcgroup()?`.
- On v1, `Manager::mounts()` for both `FsManager` and `SystemdManager` now
  selects the first matching mount in `/proc/self/mountinfo` order when a
  controller has duplicate mounts, replacing 0.5.1's last-match behavior.
  This matches cgroup handle selection; callers constructing paths from
  this map may observe a different mount point or bind mount view.

## Disclaimer

This crate is licensed under:

- MIT License (see LICENSE-MIT); or
- Apache 2.0 License (see LICENSE-Apache-2.0),

at your option.

Please note that this crate is under heavy development, we will use sematic
versioning, but during the `0.0.*` phase, no guarantees are made about
backwards compatibility.

Regardless, check back often and thanks for taking a look!
