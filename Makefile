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

# sudo's `env_reset` strips the user environment before running the command,
# which breaks the rustup cargo shim (it needs HOME to locate the toolchain
# and PATH to find cargo itself). `sudo env VAR=value ...` sets the variables
# explicitly, which is honored regardless of env_reset / env_keep, unlike `-E`
# (which some sudoers configurations reject with "preserving the entire
# environment is not supported").
# Run `make test` (not `sudo make test`): this file self-elevates for the
# privileged targets, and sudo would strip the user PATH before make sees it.
SUDO_CARGO = sudo env "PATH=$(PATH)" "HOME=$(HOME)" cargo

test: test-systemd test-fs-manager test-systemd-manager test-integration test-unit

.PHONY: test-systemd
# Privileged: talks to the real system D-Bus. Needs root and serialization
# (`--test-threads=1`).
test-systemd:
	$(SUDO_CARGO) test --package cgroups-rs --lib \
	    -- systemd::dbus::client::tests \
	    --color always --nocapture \
		--test-threads=1

.PHONY: test-fs-manager
# Privileged: writes live cgroup files. Needs root and serialization
# (`--test-threads=1`).
test-fs-manager:
	$(SUDO_CARGO) test --all-features --package cgroups-rs \
		--lib -- manager::fs::tests \
		--color always --nocapture --test-threads=1

.PHONY: test-systemd-manager
# Privileged: drives real systemd transient units. Needs root and
# serialization (`--test-threads=1`).
test-systemd-manager:
	$(SUDO_CARGO) test --all-features --package cgroups-rs \
	  --lib -- manager::systemd::tests \
	  --color always --nocapture --test-threads=1

.PHONY: test-unit
test-unit:
	cargo test --all-features --lib -- $(PRIVILEGED_FILTERS)

# Integration tests in tests/ manipulate live cgroups and need root.
# They run inside the QEMU guests in CI; this target is for local runs.
.PHONY: test-integration
test-integration:
	$(SUDO_CARGO) test --all-features --tests -- --color always --nocapture \
		--test-threads=1

.PHONY: check
check: fmt clippy


.PHONY: fmt
fmt:
	cargo fmt --all -- --check

.PHONY: clippy
clippy:
	cargo clippy --all-targets --all-features -- -D warnings

