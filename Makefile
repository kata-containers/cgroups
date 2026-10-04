# Copyright (c) 2026 Kata Contributors
#
# SPDX-License-Identifier: Apache-2.0 or MIT
#

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
	cargo package --all-features
	cargo publish --dry-run --all-features

.PHONY: build
build: debug

#
# Tests and linters
#
# Root test targets discover executables through Cargo's recording runner while
# building unprivileged, then sudo only the finished test executable via
# ci/run-root-tests.sh. Running
# cargo itself as root leaves root-owned files in target/ and the cargo registry,
# which breaks the next unprivileged build (the .cargo-build-lock becomes
# unwritable). `sudo env PATH=...` restores the user PATH that sudo's env_reset
# strips, so the test binary still finds helper commands.
# Run `make test` (not `sudo make test`): this file self-elevates for the
# root targets, and sudo would strip the user PATH before make sees it.
.NOTPARALLEL: test
test: test-doc test-library test-integration

ROOT_TEST_ARGS = --color always --nocapture --test-threads=1

.PHONY: test-lib-compile
test-lib-compile:
	ci/run-root-tests.sh compile lib --all-features --package cgroups-rs --lib

# Run the complete library harness as root and serially. The live mountinfo
# canary is ignored here because only the QEMU guests guarantee its environment.
.PHONY: test-library
test-library: test-lib-compile
	ci/run-root-tests.sh run lib -- $(ROOT_TEST_ARGS)

.PHONY: test-doc
test-doc:
	cargo test --all-features --doc

.PHONY: test-unit
test-unit: test-doc
	cargo test --all-features --lib

# Integration tests in tests/ manipulate live cgroups and need root.
# They run inside the QEMU guests in CI; this target is for local runs.
# Select every integration-test target without also selecting the library
# unit-test target; quote the glob so Cargo, rather than the shell, expands it.
.PHONY: test-tests-compile
test-tests-compile:
	ci/run-root-tests.sh compile tests --all-features --test '*'

.PHONY: test-integration
test-integration: test-tests-compile
	ci/run-root-tests.sh run tests -- $(ROOT_TEST_ARGS)

.PHONY: check
check: fmt clippy


.PHONY: fmt
fmt:
	cargo fmt --all -- --check

# All-target builds enable fixture dev-dependencies; lint the library alone
# in the second pass to also check the build with fixtures disabled.
.PHONY: clippy
clippy:
	cargo clippy --all-targets --all-features -- -D warnings
	cargo clippy --lib --no-default-features -- -D warnings
