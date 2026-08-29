# CI test matrix

This directory documents how tests are classified and where they run.
The goal is that ordinary development and CI runs do not require root
privileges, while the small set of tests that manipulate live cgroups runs
in controlled QEMU guests instead of on the GitHub runner host.

See `qemu/README.md` for the mechanics of the QEMU guest scripts.

## Test classification

The host suite is **unprivileged**. It contains the current library tests for
parsers and resource conversions, plus tests which use ordinary temporary
files and Linux inotify. In particular, the `fs::events` tests exercise the
real filesystem and inotify APIs, but do not read or modify the host's cgroup
hierarchy.

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

The privileged suites are listed once in the Makefile as
`PRIVILEGED_FILTERS` and are skipped by every plain `cargo test` run.
New privileged tests must live in a dedicated `mod tests` so the substring
filter keeps working.

## Where tests run

| Tier | What runs | Where | Privileges |
| --- | --- | --- | --- |
| Unprivileged library | `make test-unit` (lib tests with `$(PRIVILEGED_FILTERS)` skips) | GitHub runner directly | none |
| Controlled guest | three serialized lib suites, the `tests/` integration binaries, and live environment scenarios | QEMU guest | guest root, plus a delegated non-root service |

The QEMU job in `.github/workflows/bvt.yaml` therefore runs only the
controlled-guest suites, while the separate `test-unit` job covers the
unprivileged library tests on the GitHub runner. `make test` still runs the
three serialized suites and the integration tests on a local machine under
`sudo` for convenience, but CI never relies on privileges or cgroup layout
provided by the GitHub runner host.

## Backend and version matrix

Every guest runs both the cgroupfs and the systemd backend:

| Guest mode | cgroupfs backend | systemd backend |
| --- | --- | --- |
| Ubuntu 22.04, pure legacy v1 | cgroupfs-v1 | systemd-on-v1 |
| Ubuntu 22.04, hybrid v1/v2 | cgroupfs-v1 | systemd-on-v1 |
| Ubuntu 22.04, unified v2 | cgroupfs-v2 | systemd-on-v2 |

Guests are selected with explicit systemd cgroup-hierarchy kernel arguments.
Each guest must pass an exact mount-layout check before tests start, because
several existing tests return early when their expected cgroup version is
unavailable. A test that silently skips on the wrong hierarchy is detected by
the `UNEXPECTED_SKIP` check in `bvt.yaml` and fails the job.

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
  manager leaf, then creates a workload cgroup inside the delegated subtree,
  attaches its own child process, and removes the workload cgroup.
- A delegated root service unshares its cgroup and mount namespaces, replaces
  `/sys/fs/cgroup` with a namespace-rooted cgroup2 mount, and executes the
  nested-layout test. The test verifies the namespace-relative membership and
  mount root before creating and using a child cgroup.

These scenarios use kernel and systemd primitives directly; they do not infer
or depend on a container runtime.

## Image pinning

The guest base image is pinned by URL, filename, and SHA-256 checksum in
`bvt.yaml`. Updating the image is a deliberate change: bump the URL, the
`CGROUP_IMAGE_SHA256`, and the `actions/cache` key together.

## Scripts

| Script | Responsibility |
| --- | --- |
| `qemu/build-static-test-binaries.sh` | Cross-compile portable test harnesses |
| `qemu/boot-cgroup-test-vm.sh` | Configure, boot, and verify the requested QEMU cgroup layout |
| `qemu/run-tests-in-cgroup-vm.sh` | Transfer tests and coordinate execution over SSH |
| `qemu/run-test-binaries-in-guest.sh` | Execute controlled-guest test harnesses and environment scenarios |
| `qemu/stop-cgroup-test-vm.sh` | Stop the disposable QEMU guest |
