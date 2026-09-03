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

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
script_path="${script_dir}/$(basename -- "${BASH_SOURCE[0]}")"
repo_root="$(cd -- "${script_dir}/.." && pwd)"

target_dir="${CARGO_TARGET_DIR:-${repo_root}/target}"

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
        lib)
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

    host="$(cargo -vV | sed -n 's/^host: //p')"
    if [[ -z "${host}" ]]; then
        echo "run-root-tests.sh: cargo did not report its host target" >&2
        exit 1
    fi
    # A runner passed as a bare string (CARGO_TARGET_<triple>_RUNNER or a
    # config string) is split on whitespace without honoring quotes or
    # backslashes, so a checkout path containing spaces can never survive it
    # intact. Instead pass an array-valued target.<triple>.runner through
    # --config, which Cargo keeps verbatim element by element; the path only
    # needs TOML basic-string escaping (tab/CR/LF included, since raw control
    # characters are invalid in TOML strings). --config overrides both the
    # runner environment variable and any config-file runner.
    runner_path=${script_path//\\/\\\\}
    runner_path=${runner_path//\"/\\\"}
    runner_path=${runner_path//$'\t'/\\t}
    runner_path=${runner_path//$'\r'/\\r}
    runner_path=${runner_path//$'\n'/\\n}

    (
        export CGROUPS_ROOT_TEST_MANIFEST="${tmp_manifest}"
        cargo test \
            --config "target.${host}.runner=[\"${runner_path}\", 'capture']" \
            "${target_flags[@]}" "$@"
    )
    sort -u -o "${tmp_manifest}" "${tmp_manifest}"

    if [[ ! -s "${tmp_manifest}" ]]; then
        echo "run-root-tests.sh: no test executables matched mode '${mode}'" >&2
        exit 1
    fi

    # Validate the captured executables against the repo's target layout so a
    # runner misconfiguration or mode/target-flag mismatch fails here, instead
    # of `run` sudo-executing wrong binaries later. No external JSON tooling:
    # the lib target is named after the package (hyphens become underscores),
    # and auto-discovered integration tests are named after tests/<name>.rs or
    # tests/<name>/main.rs.
    lib_target="$(sed -n '/^\[package\]/,/^\[/ s/^name[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "${repo_root}/Cargo.toml" | head -n 1)"
    lib_target="${lib_target//-/_}"
    if [[ -z "${lib_target}" ]]; then
        echo "run-root-tests.sh: cannot determine the package name from ${repo_root}/Cargo.toml" >&2
        exit 1
    fi

    while IFS= read -r exe; do
        base="${exe##*/}"
        target="${base%-*}"
        case "${mode}" in
            lib)
                if [[ "${target}" != "${lib_target}" ]]; then
                    echo "run-root-tests.sh: captured executable '${base}' does not match mode 'lib'" >&2
                    exit 1
                fi
                ;;
            tests)
                if [[ ! -f "${repo_root}/tests/${target}.rs" && ! -f "${repo_root}/tests/${target}/main.rs" ]]; then
                    echo "run-root-tests.sh: captured executable '${base}' does not match mode 'tests'" >&2
                    exit 1
                fi
                ;;
        esac
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
