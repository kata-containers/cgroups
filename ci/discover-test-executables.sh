#!/usr/bin/env bash
#
# Build Rust test targets and use Cargo's artifact messages to record each
# executable as:
#   <target kind> TAB <target name> TAB <executable path>
#
# `profile.test` identifies test harnesses, while `target.kind` distinguishes
# library unit tests from integration tests. This metadata is authoritative;
# target-selection flags can request more than one kind of test target.

set -euo pipefail

readonly OUTPUT_MANIFEST="${1:?usage: discover-test-executables.sh OUTPUT_MANIFEST [cargo-test-args]...}"
shift

if ! command -v cargo >/dev/null; then
    echo "required command is missing: cargo" >&2
    exit 1
fi
if ! command -v jq >/dev/null; then
    echo "required command is missing: jq" >&2
    exit 1
fi

artifacts="$(mktemp)"
manifest="$(mktemp)"
trap 'rm -f "${artifacts}" "${manifest}"' EXIT

cargo test --no-run --message-format=json "$@" >"${artifacts}"

# The manifest is tab-delimited, so reject metadata that cannot be represented
# unambiguously. Test artifacts currently have one Cargo target kind (`lib`,
# `test`, `bin`, and so on); preserving that value lets callers validate it
# against the mode they requested.
jq --raw-output '
    select(
        .reason == "compiler-artifact"
        and .profile.test == true
        and .executable != null
    )
    | if (.target.kind | type) != "array" or (.target.kind | length) != 1 then
        error("test artifact has zero or multiple target kinds: \(.target.kind)")
      elif ([.target.kind[0], .target.name, .executable]
            | any(type != "string" or test("[\\t\\r\\n]"))) then
        error("test artifact metadata contains an unsupported tab or newline")
      else
        [.target.kind[0], .target.name, .executable] | join("\t")
      end
' "${artifacts}" >"${manifest}"

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
