# CI test matrix

This directory documents how tests are classified and where they run.
The goal is that ordinary development and CI runs do not require root
privileges, while the small set of tests that manipulate live cgroups runs
in controlled QEMU guests instead of on the GitHub runner host.

See `qemu/README.md` for the mechanics of the QEMU guest scripts.

## Test classification

A test is **privileged** when it writes cgroup state or talks to the
systemd D-Bus bus:

- creates or removes real cgroup directories
- writes controller files (`cgroup.procs`, `memory.max`, ...)
- attaches processes or threads
- connects to a real systemd instance
- watches real `memory.events` through inotify

Everything else is **host-independent**: parser tests over fixture data,
path validation, resource conversions, contract tests against recording I/O
implementations, error propagation, and capability tests. Host-dependent
reads such as `mountinfo_self()` belong to the fixture-based parser tests,
not to the privileged suite.

The privileged suites are listed once in the Makefile as
`PRIVILEGED_FILTERS` and are skipped by every plain `cargo test` run.
New privileged tests must live in a dedicated `mod tests` so the substring
filter keeps working.

## Where tests run

| Tier | What runs | Where | Privileges |
| --- | --- | --- | --- |
| Host-independent | `make test-unit` (lib tests with `$(PRIVILEGED_FILTERS)` skips) | GitHub runner directly | none |
| Privileged | three serialized lib suites plus the `tests/` integration binaries | QEMU guest | guest root |

The QEMU job in `.github/workflows/bvt.yaml` therefore runs only the
privileged suites, while the separate `test-unit` job covers the
host-independent tests on the GitHub runner. `make test` still runs the
three serialized suites and the integration tests on a local machine under
`sudo` for convenience, but CI never relies on host privileges.

## Backend and version matrix

Every guest runs both the cgroupfs and the systemd backend, so each guest
covers two of the four required combinations:

| Guest mode | cgroupfs backend | systemd backend |
| --- | --- | --- |
| Ubuntu 22.04, cgroup v1 | cgroupfs-v1 | systemd-on-v1 |
| Ubuntu 22.04, cgroup v2 | cgroupfs-v2 | systemd-on-v2 |

Guests are selected with an explicit `systemd.unified_cgroup_hierarchy=<0|1>`
kernel argument. Each guest must pass an exact hierarchy check before tests
start, because several existing tests return early when their expected
cgroup version is unavailable. A test that silently skips on the wrong
hierarchy is detected by the `UNEXPECTED_SKIP` check in `bvt.yaml` and fails
the job.

## Guest environments and hierarchy checks

| Guest mode | Kernel argument | Hierarchy check |
| --- | --- | --- |
| cgroup v1 | `systemd.unified_cgroup_hierarchy=0` | `grep -qw systemd.unified_cgroup_hierarchy=0 /proc/cmdline`, `/sys/fs/cgroup` is not `cgroup2fs`, at least one `cgroup` mount |
| cgroup v2 | `systemd.unified_cgroup_hierarchy=1` | `grep -qw systemd.unified_cgroup_hierarchy=1 /proc/cmdline`, `/sys/fs/cgroup` is `cgroup2fs`, `/sys/fs/cgroup/cgroup.controllers` exists |

Note: on Ubuntu 22.04 the `unified_cgroup_hierarchy=0` guest runs a hybrid
layout (cgroup v1 hierarchies plus a unified hierarchy), so the v1 guest
also covers hybrid-mode behavior. It is not a pure v1-only environment.

## Image pinning

The guest base image is pinned by URL, filename, and SHA-256 checksum in
`bvt.yaml`. Updating the image is a deliberate change: bump the URL, the
`CGROUP_IMAGE_SHA256`, and the `actions/cache` key together.

## Scripts

| Script | Responsibility |
| --- | --- |
| `qemu/build-static-test-binaries.sh` | Cross-compile portable test harnesses |
| `qemu/boot-cgroup-test-vm.sh` | Configure, boot, and verify a v1 or v2 QEMU guest |
| `qemu/run-tests-in-cgroup-vm.sh` | Transfer tests and coordinate execution over SSH |
| `qemu/run-test-binaries-in-guest.sh` | Execute the privileged test harnesses inside the guest |
| `qemu/stop-cgroup-test-vm.sh` | Stop the disposable QEMU guest |
