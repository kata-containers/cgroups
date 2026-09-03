#!/usr/bin/env bash
#
# Run the compiled Rust test harnesses inside a cgroup test VM.

set -euo pipefail

readonly USAGE="usage: run-test-binaries-in-guest.sh TEST_DIR HIERARCHY"
readonly TEST_DIR="${1:?${USAGE}}"
readonly HIERARCHY="${2:?${USAGE}}"

cd "${TEST_DIR}"

cleanup_failed_test() {
    # A failed test can leave a spawned helper holding the SSH channel open.
    # The VM is disposable, so terminate only the helper commands used by
    # this suite before returning.
    sudo pkill -KILL -x sleep || true
    sudo pkill -KILL -x yes || true
}

run_test() {
    local test_binary="$1"
    shift

    echo
    echo "Running ${test_binary} $*"

    local result=0
    # Do not let the test consume executable paths from the loop manifest.
    sudo -E "./${test_binary}" "$@" --color always --nocapture \
        --test-threads=1 </dev/null || result=$?
    if ((result != 0)); then
        cleanup_failed_test
        exit "${result}"
    fi
}

mapfile -t library_tests < <(grep -E '^cgroups_rs-' manifest || true)
if ((${#library_tests[@]} != 1)); then
    echo "expected exactly one library test executable" >&2
    exit 1
fi
library_test="${library_tests[0]}"

# Match the phases in the Makefile: cgroup-manipulating suites are isolated
# and sequential, followed by integration test binaries from manifest.
run_test "${library_test}" systemd::dbus::client::tests
run_test "${library_test}" manager::fs::tests
run_test "${library_test}" manager::systemd::tests
run_test "${library_test}" manager::fs::parse_tests::test_live_mountinfo_canary --exact

while IFS= read -r test_binary; do
    [[ "${test_binary}" == "${library_test}" ]] && continue
    run_test "${test_binary}"
done < manifest

if [[ "${HIERARCHY}" == "unified-v2" ]]; then
    mapfile -t environment_tests < <(grep -E '^environment-' manifest || true)
    if ((${#environment_tests[@]} != 1)); then
        echo "expected exactly one environment integration-test executable" >&2
        exit 1
    fi
    environment_test="${environment_tests[0]}"

    echo
    echo "Running delegated cgroup v2 test as the unprivileged runner user"
    sudo systemd-run \
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
    sudo systemd-run \
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
            mount --make-rprivate /
            umount /sys/fs/cgroup
            mount -t cgroup2 none /sys/fs/cgroup
            exec "$@"
        ' bash "${TEST_DIR}/${environment_test}" \
        cgroup_namespace_nested_v2 --exact --ignored --color always --nocapture \
        --test-threads=1
fi
