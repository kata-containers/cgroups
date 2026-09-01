#!/usr/bin/env bash
#
# Build Rust test binaries unprivileged, then run them as root.
#
# `sudo cargo test` runs cargo itself as root, which leaves root-owned files in
# target/ and ~/.cargo/registry; the next unprivileged build then fails with
# "Permission denied" on target/debug/.cargo-build-lock. Building with a
# recording target runner as the invoking user and sudo'ing only the finished
# test executable avoids that, mirroring ci/qemu/build-static-test-binaries.sh +
# ci/qemu/run-test-binaries-in-guest.sh.
#
# The compile and run phases are split so that several suites sharing one test
# binary (the three privileged lib suites) compile once and reuse it, instead
# of each asking Cargo to prepare the same test target again. Each kind writes
# its own manifest (target/.test-binaries-<kind>), so concurrent lib/tests runs
# (e.g. `make -j`) never clobber each other.
#
# Usage:
#   ci/run-root-tests.sh compile <lib|tests> <cargo-test-args>...
#   ci/run-root-tests.sh run <lib|tests> -- <test-binary-args>...
#
# `compile lib`   writes the library unit-test binary path to the manifest.
# `compile tests` writes the integration-test binary paths to the manifest.
# `run` sudo-executes every binary in the manifest with the args after "--".

set -euo pipefail

target_dir="${CARGO_TARGET_DIR:-target}"

cmd="${1:?usage: run-root-tests.sh <compile <lib|tests>|run <lib|tests>> ...}"
shift

case "${cmd}" in
# Internal Cargo runner entry point: record the executable without running it.
capture)
    manifest="${CGROUPS_ROOT_TEST_MANIFEST:?capture: manifest is not set}"
    executable="${1:?capture: want test executable}"
    printf '%s\n' "${executable}" >>"${manifest}"
    ;;

compile)
    mode="${1:?compile: want <lib|tests>}"
    shift
    case "${mode}" in
        lib)   ;;
        tests) ;;
        *) echo "run-root-tests.sh: unknown mode '${mode}' (want 'lib' or 'tests')" >&2; exit 2 ;;
    esac

    tmp_manifest="$(mktemp)"
    trap 'rm -f "${tmp_manifest}"' EXIT

    host="$(cargo -vV | sed -n 's/^host: //p')"
    if [[ -z "${host}" ]]; then
        echo "run-root-tests.sh: cargo did not report its host target" >&2
        exit 1
    fi
    runner_env="CARGO_TARGET_${host^^}_RUNNER"
    runner_env="${runner_env//-/_}"

    (
        export "${runner_env}=ci/run-root-tests.sh capture"
        export CGROUPS_ROOT_TEST_MANIFEST="${tmp_manifest}"
        cargo test "$@"
    )
    sort -u -o "${tmp_manifest}" "${tmp_manifest}"

    if [[ ! -s "${tmp_manifest}" ]]; then
        echo "run-root-tests.sh: no test executables matched mode '${mode}'" >&2
        exit 1
    fi

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

    while IFS= read -r exe; do
        echo
        echo "Running (root): ${exe##*/}" "$@"
        # Do not let the test consume executable paths from the loop manifest.
        sudo env "PATH=${PATH}" "${exe}" "$@" </dev/null
    done <"${manifest}"
    ;;

*)
    echo "run-root-tests.sh: unknown command '${cmd}' (want 'compile' or 'run')" >&2
    exit 2
    ;;
esac
