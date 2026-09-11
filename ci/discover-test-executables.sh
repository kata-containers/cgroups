#!/usr/bin/env bash
#
# Build Rust test targets with a recording Cargo runner and record each
# executable as:
#   <target kind> TAB <target name> TAB <executable path>
#
# Cargo invokes a configured runner with the executable path as its first
# argument. The capture mode records that path and exits without executing the
# test, so compilation remains unprivileged and no JSON parser is required.

set -euo pipefail

if [[ "${1:-}" == "capture" ]]; then
    manifest="${CGROUP_TEST_EXECUTABLE_MANIFEST:?capture: manifest is not set}"
    executable="${2:?capture: want test executable}"
    printf '%s\n' "${executable}" >>"${manifest}"
    exit 0
fi

readonly OUTPUT_MANIFEST="${1:?usage: discover-test-executables.sh OUTPUT_MANIFEST [cargo-test-args]...}"
shift

if ! command -v cargo >/dev/null; then
    echo "required command is missing: cargo" >&2
    exit 1
fi

target_kind=""
for arg in "$@"; do
    case "${arg}" in
        --lib)
            target_kind="lib"
            ;;
        --test|--test=*)
            target_kind="test"
            ;;
        --tests)
            target_kind="test"
            ;;
    esac
done
if [[ -z "${target_kind}" ]]; then
    echo "discover-test-executables.sh: pass --lib, --tests, or --test to identify target kind" >&2
    exit 2
fi

script_path="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/$(basename -- "${BASH_SOURCE[0]}")"
host="$(cargo -vV | sed -n 's/^host: //p')"
if [[ -z "${host}" ]]; then
    echo "discover-test-executables.sh: cargo did not report its host target" >&2
    exit 1
fi
target="${host}"
expect_target_value=false
for arg in "$@"; do
    if ${expect_target_value}; then
        target="${arg}"
        expect_target_value=false
        continue
    fi
    case "${arg}" in
        --target)
            expect_target_value=true
            ;;
        --target=*)
            target="${arg#--target=}"
            ;;
    esac
done
if ${expect_target_value} || [[ -z "${target}" ]]; then
    echo "discover-test-executables.sh: --target requires a target triple" >&2
    exit 2
fi

captured="$(mktemp)"
manifest="$(mktemp)"
trap 'rm -f "${captured}" "${manifest}"' EXIT

# A runner passed as a bare string is split on whitespace and cannot preserve
# paths containing spaces. Use an array-valued target runner and escape the
# path as a TOML basic string, matching Cargo's own configuration rules.
runner_path=${script_path//\\/\\\\}
runner_path=${runner_path//\"/\\\"}
runner_path=${runner_path//$'\t'/\\t}
runner_path=${runner_path//$'\r'/\\r}
runner_path=${runner_path//$'\n'/\\n}

(
    export CGROUP_TEST_EXECUTABLE_MANIFEST="${captured}"
    cargo test \
        --config "target.${target}.runner=[\"${runner_path}\", 'capture']" \
        "$@"
)
sort -u -o "${captured}" "${captured}"

if [[ ! -s "${captured}" ]]; then
    echo "cargo did not produce any test executables" >&2
    exit 1
fi

while IFS= read -r executable; do
    executable_name="${executable##*/}"
    target_name="${executable_name%-*}"
    if [[ -z "${target_name}" || "${target_name}" == "${executable_name}" ]]; then
        echo "cannot determine target name from executable '${executable_name}'" >&2
        exit 1
    fi
    printf '%s\t%s\t%s\n' "${target_kind}" "${target_name}" "${executable}" >>"${manifest}"
done <"${captured}"

sort -u -o "${manifest}" "${manifest}"
if [[ ! -s "${manifest}" ]]; then
    echo "cargo did not produce any test executables" >&2
    exit 1
fi

mkdir -p "$(dirname -- "${OUTPUT_MANIFEST}")"
mv "${manifest}" "${OUTPUT_MANIFEST}"

echo "Discovered $(wc -l <"${OUTPUT_MANIFEST}") test executable(s):"
while IFS=$'\t' read -r discovered_kind discovered_name executable; do
    printf '  %s %s: %s\n' "${discovered_kind}" "${discovered_name}" "${executable}"
done <"${OUTPUT_MANIFEST}"
