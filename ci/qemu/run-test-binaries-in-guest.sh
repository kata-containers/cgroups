#!/usr/bin/env bash
#
# Copyright (c) 2026 Kata Contributors
#
# SPDX-License-Identifier: Apache-2.0 or MIT
#
#
# Run the compiled Rust test harnesses inside a cgroup test VM.

set -euo pipefail

readonly USAGE="usage: run-test-binaries-in-guest.sh TEST_DIR HIERARCHY"
readonly TEST_DIR="${1:?${USAGE}}"
readonly HIERARCHY="${2:?${USAGE}}"

if ((EUID != 0)); then
    echo "guest test runner must run as root; got EUID ${EUID}" >&2
    exit 1
fi

cd "${TEST_DIR}"

cleanup_failed_test() {
    # A failed test can leave a spawned helper holding the SSH channel open.
    # The VM is disposable, so terminate only the helper commands used by
    # this suite before returning.
    pkill -KILL -x sleep || true
    pkill -KILL -x yes || true
}

run_test() {
    local test_binary="$1"
    shift

    echo
    echo "Running ${test_binary} $*"

    local result=0
    # Do not let the test consume executable paths from the loop manifest.
    "./${test_binary}" "$@" --color always --nocapture \
        --test-threads=1 </dev/null || result=$?
    if ((result != 0)); then
        cleanup_failed_test
        exit "${result}"
    fi
}

require_test() {
    local test_binary="$1"
    local test_name="$2"

    if ! "./${test_binary}" --list --format terse | grep -Fqx "${test_name}: test"; then
        echo "required test '${test_name}' not found in ${test_binary}" >&2
        exit 1
    fi
}

library_tests=()
integration_tests=()
environment_tests=()
while IFS=$'\t' read -r target_kind target_name test_binary; do
    case "${target_kind}" in
        lib)
            library_tests+=("${test_binary}")
            ;;
        test)
            integration_tests+=("${test_binary}")
            if [[ "${target_name}" == "environment" ]]; then
                environment_tests+=("${test_binary}")
            fi
            ;;
        *)
            echo "unsupported test target kind '${target_kind}' for ${target_name}" >&2
            exit 1
            ;;
    esac
done < manifest

if ((${#library_tests[@]} != 1)); then
    echo "expected exactly one library test executable" >&2
    exit 1
fi
library_test="${library_tests[0]}"

# Run the complete library harness once. Privileged tests cannot silently skip
# here because this script has already verified its effective UID.
run_test "${library_test}"

# This ignored canary depends on the guest's controlled cgroup hierarchy, not
# on root privileges, so keep its environment requirement explicit.
require_test "${library_test}" oci::fs::parse_tests::test_live_mountinfo_canary
run_test "${library_test}" oci::fs::parse_tests::test_live_mountinfo_canary --exact --ignored

for test_binary in "${integration_tests[@]}"; do
    run_test "${test_binary}"
done

if [[ "${HIERARCHY}" == "unified-v2" ]]; then
    if ((${#environment_tests[@]} != 1)); then
        echo "expected exactly one environment integration-test executable" >&2
        exit 1
    fi
    environment_test="${environment_tests[0]}"

    require_test "${environment_test}" delegated_rootless_v2
    require_test "${environment_test}" cgroup_namespace_nested_v2

    echo
    echo "Running delegated cgroup v2 test as the unprivileged runner user"
    systemd-run \
        --quiet \
        --wait \
        --collect \
        --pipe \
        --service-type=exec \
        --unit=cgroups-rs-rootless.service \
        --property=Delegate=yes \
        --property=User=runner \
        --property="WorkingDirectory=${TEST_DIR}" \
        "${TEST_DIR}/${environment_test}" \
        delegated_rootless_v2 --exact --ignored --color always --nocapture \
        --test-threads=1

    echo
    echo "Running nested cgroup v2 test in private cgroup and mount namespaces"
    systemd-run \
        --quiet \
        --wait \
        --collect \
        --pipe \
        --service-type=exec \
        --unit=cgroups-rs-namespace.service \
        --property=Delegate=yes \
        /usr/bin/unshare --cgroup --mount --fork \
        /bin/bash -c '
            set -euo pipefail
            if ((EUID != 0)); then
                echo "namespace test launcher must run as root; got EUID ${EUID}" >&2
                exit 1
            fi
            mount --make-rprivate /
            umount /sys/fs/cgroup
            mount -t cgroup2 none /sys/fs/cgroup
            exec "$@"
        ' bash "${TEST_DIR}/${environment_test}" \
        cgroup_namespace_nested_v2 --exact --ignored --color always --nocapture \
        --test-threads=1
fi
