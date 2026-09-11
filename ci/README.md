# CI test matrix

This directory documents how tests are classified and where they run.
The goal is that ordinary development and CI runs do not require root
privileges, while the small set of tests that manipulate live cgroups runs
in controlled QEMU guests instead of on the GitHub runner host.

See `qemu/README.md` for the mechanics of the QEMU guest scripts.

## Test classification

The host suite is **unprivileged**. It runs the complete library harness, but
tests which require root call `skip_if_not_root!()` before touching the live
system. It therefore includes parser and resource-conversion tests, plus tests
which use ordinary temporary files and Linux inotify. In particular, the
`fs::events` tests exercise the real filesystem and inotify APIs, but do not
read or modify the host's cgroup hierarchy.

The controlled-guest suite contains tests which depend on a specific live
cgroup layout or need elevated privileges:

- creates or removes real cgroup directories
- writes controller files (`cgroup.procs`, `memory.max`, ...)
- attaches processes or threads
- connects to a real systemd instance
- reads live discovery inputs as a kernel-drift canary
- runs inside a delegated subtree or a private cgroup namespace

Parser tables protect expected behavior against source changes. The live
`mountinfo_self()` canary runs in the controlled guests so it sees each
intentional hierarchy layout. Validated-path, recording-I/O contract,
capability, and systematic error-propagation tests are planned for later
refactoring phases; they are not part of the current host suite.

Each root requirement lives beside the test that needs it instead of being
inferred from a module name. The macro checks the effective UID and prints a
clear skip reason. Because Rust reports its early return as a passed test, both
root runners verify EUID 0 before starting any test executable. The live
mountinfo canary is ignored by default and runs explicitly in each controlled
QEMU guest because its requirement is the guest environment rather than root.

## Where tests run

| Tier | What runs | Where | Privileges |
| --- | --- | --- | --- |
| Unprivileged library | `make test-unit` (complete lib harness; root-gated tests return early) | GitHub runner directly | none |
| Controlled guest | complete serialized lib harness, every `tests/` integration binary, the live canary, and dedicated environment scenarios | QEMU guest | guest root, plus a delegated non-root service |

The `test-binaries` job in `.github/workflows/bvt.yaml` compiles the static test
executables once and publishes them as one artifact. All three QEMU hierarchy
jobs consume that artifact, run the complete library harness as root with
`--test-threads=1`, and then run every integration test binary. The separate
`test-unit` job covers tests that can run on the unprivileged GitHub runner.
`make test` follows the root execution model locally for convenience, but
compilation remains unprivileged and CI never relies on privileges or cgroup
layout provided by the GitHub runner host.

Workflow-level concurrency cancels superseded runs for the same pull request,
and Cargo registry, Git, and target directories are cached per job and Rust
version. All jobs have explicit timeouts and the workflow token is limited to
read-only repository contents. Third-party actions are pinned to full commit
SHAs with their release major documented in comments.

## Backend and version matrix

Every guest runs both the cgroupfs and the systemd backend:

| Guest mode | cgroupfs backend | systemd backend |
| --- | --- | --- |
| Ubuntu 22.04, pure legacy v1 | cgroupfs-v1 | systemd-on-v1 |
| Ubuntu 22.04, hybrid v1/v2 | cgroupfs-v1 | systemd-on-v1 |
| Ubuntu 22.04, unified v2 | cgroupfs-v2 | systemd-on-v2 |

Guests are selected with explicit systemd cgroup-hierarchy kernel arguments.
Each guest must pass an exact mount-layout check before tests start, because
version-specific tests use `skip_if_cgroups_v1!()` or
`skip_if_cgroups_v2!()` when their supported hierarchy is unavailable. These
macros emit a standard skip message. The `UNEXPECTED_SKIP` check in `bvt.yaml`
rejects the opposite message for each guest, so a test expected to run cannot
silently pass after detecting the wrong hierarchy.

## Guest environments and hierarchy checks

| Guest mode | Kernel argument | Hierarchy check |
| --- | --- | --- |
| pure legacy v1 | `systemd.unified_cgroup_hierarchy=0 systemd.legacy_systemd_cgroup_controller=1` | `/sys/fs/cgroup` is not `cgroup2fs`, at least one `cgroup` mount, no `cgroup2` mount |
| hybrid v1/v2 | `systemd.unified_cgroup_hierarchy=0 systemd.legacy_systemd_cgroup_controller=0` | `/sys/fs/cgroup` is not `cgroup2fs`, both `cgroup` and `cgroup2` mounts exist |
| unified v2 | `systemd.unified_cgroup_hierarchy=1` | `/sys/fs/cgroup` is `cgroup2fs`, `cgroup.controllers` exists, no v1 `cgroup` mount |

## Delegation and namespace scenarios

The unified-v2 guest also runs two ignored integration tests explicitly in
controlled environments:

- A transient system service with `Delegate=yes` and `User=runner` executes
  the cgroupfs test as a non-root user. The test first moves itself into a
  manager leaf, enables the delegated `pids` controller, then creates a
  workload cgroup, sets and reads back `pids.max`, attaches a child process,
  and removes the workload cgroup.
- A delegated root service unshares its cgroup and mount namespaces, replaces
  `/sys/fs/cgroup` with a namespace-rooted cgroup2 mount, and executes the
  nested-layout test. The test moves both itself and the waiting
  `unshare --fork` parent out of the namespace root before enabling `pids`,
  then performs the same limit and child-cgroup checks.

These scenarios use kernel and systemd primitives directly; they do not infer
or depend on a container runtime. Before starting either launcher, the guest
runner checks the test harness's exact `--list` output so renaming one of these
tests cannot silently remove its coverage.

On a failed guest job, the diagnostics artifact contains the test harness log,
the complete guest boot journal, the serial console log, and the QEMU log. The
journal is collected after every guest run so it is also available when the
workflow detects an unexpected hierarchy skip after the runner exits.

## Image pinning

The guest base image is pinned by URL, filename, and SHA-256 checksum in
`bvt.yaml`. Updating the image is a deliberate change: bump the URL, the
`CGROUP_IMAGE_SHA256`, and the `actions/cache` key together.

## Scripts

| Script | Responsibility |
| --- | --- |
| `discover-test-executables.sh` | Compile with Cargo's recording runner and record target kinds, names, and executable paths |
| `qemu/build-static-test-binaries.sh` | Cross-compile and package the discovered portable test harnesses |
| `qemu/boot-cgroup-test-vm.sh` | Configure, boot, and verify the requested QEMU cgroup layout |
| `qemu/run-tests-in-cgroup-vm.sh` | Transfer tests and coordinate execution over SSH |
| `qemu/run-test-binaries-in-guest.sh` | Execute controlled-guest test harnesses and environment scenarios |
| `qemu/stop-cgroup-test-vm.sh` | Stop the disposable QEMU guest |
