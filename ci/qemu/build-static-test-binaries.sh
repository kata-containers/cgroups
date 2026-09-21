#!/usr/bin/env bash
#
# Copyright (c) 2026 Kata Contributors
#
# SPDX-License-Identifier: Apache-2.0 or MIT
#
#
# Build portable test executables on the GitHub runner.  The executables are
# copied into the cgroup VM and run there, avoiding a Rust build under QEMU
# software emulation.

set -euo pipefail

readonly TARGET="x86_64-unknown-linux-musl"
readonly OUTPUT_DIR="${1:?usage: build-static-test-binaries.sh OUTPUT_DIR}"
readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly DISCOVERY_SCRIPT="${SCRIPT_DIR}/../discover-test-executables.sh"

if [[ -e "${OUTPUT_DIR}" ]]; then
    echo "output directory already exists: ${OUTPUT_DIR}" >&2
    exit 1
fi

mkdir -p "${OUTPUT_DIR}"

library_executables="$(mktemp)"
integration_executables="$(mktemp)"
executables="$(mktemp)"
manifest="$(mktemp)"
trap 'rm -f "${library_executables}" "${integration_executables}" "${executables}" "${manifest}"' EXIT

"${DISCOVERY_SCRIPT}" "${library_executables}" \
    --all-features \
    --target "${TARGET}" \
    --lib

"${DISCOVERY_SCRIPT}" "${integration_executables}" \
    --all-features \
    --target "${TARGET}" \
    --test '*'

cat "${library_executables}" "${integration_executables}" | sort -u >"${executables}"

while IFS=$'\t' read -r target_kind target_name executable; do
    executable_name="$(basename -- "${executable}")"
    destination="${OUTPUT_DIR}/${executable_name}"
    if [[ -e "${destination}" ]]; then
        echo "duplicate packaged executable name: ${executable_name}" >&2
        exit 1
    fi
    cp "${executable}" "${destination}"
    strip "${destination}"

    if readelf -l "${destination}" | grep -q "Requesting program interpreter"; then
        echo "test executable is dynamically linked: ${destination}" >&2
        exit 1
    fi
    printf '%s\t%s\t%s\n' "${target_kind}" "${target_name}" "${executable_name}" >>"${manifest}"
done <"${executables}"

sort -u -o "${manifest}" "${manifest}"
mv "${manifest}" "${OUTPUT_DIR}/manifest"

echo "Built $(wc -l <"${OUTPUT_DIR}/manifest") static test executables:"
while IFS=$'\t' read -r target_kind target_name executable; do
    printf '  %s %s: %s\n' "${target_kind}" "${target_name}" "${executable}"
done <"${OUTPUT_DIR}/manifest"
