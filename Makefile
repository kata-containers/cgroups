all: debug fmt test

#
# Build
#

.PHONY: debug
debug:
	RUSTFLAGS="--deny warnings" cargo build

.PHONY: release
release:
	cargo build --release

.PHONY: build
build: debug

#
# Tests and linters
#
PRIVILEGED_FILTERS = --skip systemd::dbus::client::tests --skip manager::fs::tests --skip manager::systemd::tests

# Privileged targets build unprivileged with a recording Cargo runner and then
# sudo only the finished test executable, via ci/run-root-tests.sh. Running
# cargo itself as root leaves root-owned files in target/ and the cargo registry,
# which breaks the next unprivileged build (the .cargo-build-lock becomes
# unwritable). `sudo env PATH=...` restores the user PATH that sudo's env_reset
# strips, so the test binary still finds helper commands.
# Run `make test` (not `sudo make test`): this file self-elevates for the
# privileged targets, and sudo would strip the user PATH before make sees it.
.NOTPARALLEL: test
test: test-systemd test-fs-manager test-systemd-manager test-integration test-unit

# The three privileged lib suites run the same library test binary, differing
# only in the filter argument. Shared cargo flags are factored out here; each
# suite sets its own PRIV_FILTER via a target-specific variable. The binary is
# prepared once by test-lib-compile and reused by all three, so Cargo is invoked
# once to prepare it, not three times.
PRIV_LIB_CARGO = --all-features --package cgroups-rs --lib
PRIV_TEST_ARGS = --color always --nocapture --test-threads=1

.PHONY: test-lib-compile
test-lib-compile:
	ci/run-root-tests.sh compile lib $(PRIV_LIB_CARGO)

# Privileged lib suites: talk to the real system D-Bus, write live cgroup
# files, and drive real systemd transient units respectively. Need root and
# serialization (`--test-threads=1`).
test-systemd:         PRIV_FILTER = systemd::dbus::client::tests
test-fs-manager:      PRIV_FILTER = manager::fs::tests
test-systemd-manager: PRIV_FILTER = manager::systemd::tests

.PHONY: test-systemd test-fs-manager test-systemd-manager
test-systemd test-fs-manager test-systemd-manager: test-lib-compile
	ci/run-root-tests.sh run lib -- $(PRIV_FILTER) $(PRIV_TEST_ARGS)

.PHONY: test-doc
test-doc:
	cargo test --all-features --doc

.PHONY: test-unit
test-unit: test-doc
	cargo test --all-features --lib -- $(PRIVILEGED_FILTERS)

# Integration tests in tests/ manipulate live cgroups and need root.
# They run inside the QEMU guests in CI; this target is for local runs.
# Select every integration-test target without also selecting the library
# unit-test target; quote the glob so Cargo, rather than the shell, expands it.
.PHONY: test-tests-compile
test-tests-compile:
	ci/run-root-tests.sh compile tests --all-features --test '*'

.PHONY: test-integration
test-integration: test-tests-compile
	ci/run-root-tests.sh run tests -- --color always --nocapture --test-threads=1

.PHONY: check
check: fmt clippy


.PHONY: fmt
fmt:
	cargo fmt --all -- --check

.PHONY: clippy
clippy:
	cargo clippy --all-targets --all-features -- -D warnings

