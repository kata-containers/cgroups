#!/usr/bin/env bash
#
# Copy statically linked test executables into a cgroup VM and run them
# sequentially.  Running every executable covers library and integration tests.

set -euo pipefail

readonly USAGE="usage: run-tests-in-cgroup-vm.sh STATE_DIR TEST_BINARIES PRIVATE_KEY HIERARCHY"
readonly STATE_DIR="${1:?${USAGE}}"
readonly TEST_BINARIES="${2:?${USAGE}}"
readonly SSH_PORT="${CGROUP_VM_SSH_PORT:-2222}"
readonly SSH_USER="runner"
readonly PRIVATE_KEY="${3:?${USAGE}}"
readonly HIERARCHY="${4:?${USAGE}}"
readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly GUEST_TEST_RUNNER="${SCRIPT_DIR}/run-test-binaries-in-guest.sh"

case "${HIERARCHY}" in
    legacy-v1)
        hierarchy_check='
            grep -Fqw systemd.unified_cgroup_hierarchy=0 /proc/cmdline &&
            grep -Fqw systemd.legacy_systemd_cgroup_controller=1 /proc/cmdline &&
            test "$(stat -fc %T /sys/fs/cgroup)" != cgroup2fs &&
            test -n "$(findmnt -rn -t cgroup -o TARGET)" &&
            test -z "$(findmnt -rn -t cgroup2 -o TARGET)"
        '
        ;;
    hybrid-v1)
        hierarchy_check='
            grep -Fqw systemd.unified_cgroup_hierarchy=0 /proc/cmdline &&
            grep -Fqw systemd.legacy_systemd_cgroup_controller=0 /proc/cmdline &&
            test "$(stat -fc %T /sys/fs/cgroup)" != cgroup2fs &&
            test -n "$(findmnt -rn -t cgroup -o TARGET)" &&
            test -n "$(findmnt -rn -t cgroup2 -o TARGET)"
        '
        ;;
    unified-v2)
        hierarchy_check='
            grep -Fqw systemd.unified_cgroup_hierarchy=1 /proc/cmdline &&
            test "$(stat -fc %T /sys/fs/cgroup)" = cgroup2fs &&
            test -f /sys/fs/cgroup/cgroup.controllers &&
            test -z "$(findmnt -rn -t cgroup -o TARGET)"
        '
        ;;
    *)
        echo "unsupported cgroup hierarchy: ${HIERARCHY}" >&2
        exit 1
        ;;
esac

if [[ ! -f "${STATE_DIR}/qemu.pid" ]]; then
    echo "QEMU pid file is missing from ${STATE_DIR}" >&2
    exit 1
fi
if [[ ! -f "${TEST_BINARIES}/manifest" ]]; then
    echo "test manifest is missing from ${TEST_BINARIES}" >&2
    exit 1
fi
if [[ ! -f "${PRIVATE_KEY}" ]]; then
    echo "SSH private key is missing: ${PRIVATE_KEY}" >&2
    exit 1
fi
if [[ ! -f "${GUEST_TEST_RUNNER}" ]]; then
    echo "guest test runner is missing: ${GUEST_TEST_RUNNER}" >&2
    exit 1
fi

ssh_options=(
    -i "${PRIVATE_KEY}"
    -p "${SSH_PORT}"
    -o BatchMode=yes
    -o ConnectTimeout=10
    -o StrictHostKeyChecking=no
    -o UserKnownHostsFile=/dev/null
)

collect_guest_journal() {
    local output="${STATE_DIR}/guest-journal.log"
    echo "Collecting guest journal: ${output}" >&2
    ssh "${ssh_options[@]}" "${SSH_USER}@127.0.0.1" \
        'sudo journalctl --boot --no-pager --output=short-precise' \
        >"${output}" 2>&1 || true
}

on_exit() {
    local result=$?
    trap - EXIT
    # Collect on success too: the workflow can subsequently turn an unexpected
    # hierarchy skip into a failure after this script has exited successfully.
    collect_guest_journal
    exit "${result}"
}
trap on_exit EXIT

echo "Guest hierarchy:"
ssh "${ssh_options[@]}" "${SSH_USER}@127.0.0.1" \
    'set -e;
     systemd --version | head -n 1;
     findmnt -rn -t cgroup,cgroup2 -o FSTYPE,TARGET,OPTIONS;
     echo;
     cat /proc/cgroups'

ssh "${ssh_options[@]}" "${SSH_USER}@127.0.0.1" \
    "${hierarchy_check}"

ssh "${ssh_options[@]}" "${SSH_USER}@127.0.0.1" \
    'mkdir -p /tmp/cgroups-rs-tests'

tar -czf - \
    -C "${TEST_BINARIES}" . \
    -C "${SCRIPT_DIR}" "$(basename "${GUEST_TEST_RUNNER}")" \
    | ssh "${ssh_options[@]}" "${SSH_USER}@127.0.0.1" \
        'tar -xzf - -C /tmp/cgroups-rs-tests'

ssh "${ssh_options[@]}" "${SSH_USER}@127.0.0.1" \
    "sudo bash /tmp/cgroups-rs-tests/run-test-binaries-in-guest.sh /tmp/cgroups-rs-tests ${HIERARCHY}"
