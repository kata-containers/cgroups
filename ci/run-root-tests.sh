#!/usr/bin/env bash
#
# Build Rust test binaries unprivileged, then run them as root.
#
# `sudo cargo test` runs cargo itself as root, which leaves root-owned files in
# target/ and ~/.cargo/registry; the next unprivileged build then fails with
# "Permission denied" on target/debug/.cargo-build-lock. Discovering binaries
# from Cargo's JSON artifact messages as the invoking user and sudo'ing only
# the finished executable avoids that. Cargo's target metadata also lets us
# reject selection flags that build the wrong kind.
#
# The compile and run phases are split so Cargo always runs unprivileged. The
# shared discovery script writes each kind's manifest
# (target/.test-binaries-<kind>), so concurrent lib/tests runs (e.g. `make -j`)
# never clobber each other.
#
# Usage:
#   ci/run-root-tests.sh compile <lib|tests> <cargo-test-args>...
#   ci/run-root-tests.sh run <lib|tests> -- <test-binary-args>...
#
# `compile lib`   writes the library unit-test binary path to the manifest.
# `compile tests` writes the integration-test binary paths to the manifest.
# `run` sudo-executes every binary in the manifest with the args after "--".

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/.." && pwd)"
discovery_script="${script_dir}/discover-test-executables.sh"

target_dir="${CARGO_TARGET_DIR:-${repo_root}/target}"

cmd="${1:?usage: run-root-tests.sh <compile <lib|tests>|run <lib|tests>> ...}"
shift

case "${cmd}" in
compile)
    mode="${1:?compile: want <lib|tests>}"
    shift
    case "${mode}" in
        lib)
            expected_kind="lib"
            has_target_flag=false
            for arg in "$@"; do
                [[ "${arg}" == "--lib" ]] && has_target_flag=true
            done
            target_flags=()
            if ! ${has_target_flag}; then
                target_flags+=(--lib)
            fi
            ;;
        tests)
            expected_kind="test"
            has_target_flag=false
            for arg in "$@"; do
                [[ "${arg}" == "--test" || "${arg}" == --test=* || "${arg}" == "--tests" ]] && has_target_flag=true
            done
            target_flags=()
            if ! ${has_target_flag}; then
                target_flags+=(--test '*')
            fi
            ;;
        *) echo "run-root-tests.sh: unknown mode '${mode}' (want 'lib' or 'tests')" >&2; exit 2 ;;
    esac

    tmp_manifest="$(mktemp)"
    trap 'rm -f "${tmp_manifest}"' EXIT

    "${discovery_script}" "${tmp_manifest}" "${target_flags[@]}" "$@"

    while IFS=$'\t' read -r target_kind target_name executable; do
        if [[ "${target_kind}" != "${expected_kind}" ]]; then
            echo "run-root-tests.sh: target '${target_name}' has kind '${target_kind}', expected '${expected_kind}'" >&2
            exit 1
        fi
        if [[ ! -x "${executable}" ]]; then
            echo "run-root-tests.sh: test executable is missing or not executable: ${executable}" >&2
            exit 1
        fi
    done <"${tmp_manifest}"

    manifest="${target_dir}/.test-binaries-${mode}"
    mkdir -p "$(dirname "${manifest}")"
    mv "${tmp_manifest}" "${manifest}"

    echo "Compiled $(wc -l <"${manifest}") test executable(s) for mode '${mode}':"
    sed 's/^/  /' "${manifest}"
    ;;

run)
    kind="${1:?run: want <lib|tests>}"
    shift
    case "${kind}" in
        lib)   ;;
        tests) ;;
        *) echo "run-root-tests.sh: unknown kind '${kind}' (want 'lib' or 'tests')" >&2; exit 2 ;;
    esac

    manifest="${target_dir}/.test-binaries-${kind}"
    if [[ ! -s "${manifest}" ]]; then
        echo "run-root-tests.sh: no compiled test binaries for '${kind}'; run 'compile ${kind}' first" >&2
        exit 1
    fi

    # Drop a leading "--" separator if present.
    [[ "${1:-}" == "--" ]] && shift

    # A root-gated Rust test returns successfully when it skips. Verify the
    # elevation independently before starting any test executable so a broken
    # sudo configuration cannot turn the privileged suite into a false pass.
    effective_uid="$(sudo env "PATH=${PATH}" id -u)"
    if [[ "${effective_uid}" != 0 ]]; then
        echo "run-root-tests.sh: privilege elevation produced EUID ${effective_uid}, expected 0" >&2
        exit 1
    fi

    while IFS=$'\t' read -r target_kind target_name exe; do
        echo
        echo "Running (root): ${target_name} (${exe##*/})" "$@"
        # Do not let the test consume executable paths from the loop manifest.
        sudo env "PATH=${PATH}" "${exe}" "$@" </dev/null
    done <"${manifest}"
    ;;

*)
    echo "run-root-tests.sh: unknown command '${cmd}' (want 'compile' or 'run')" >&2
    exit 2
    ;;
esac
