#!/usr/bin/env bash
# Run the Stage 3/4 suites in a disposable privileged container: privileged
# mode as root, then rootless mode as UID 1000 with a delegated cgroup subtree.
set -u
set -o pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
CC=${1:-${CC:-gcc}}

docker run --rm --privileged -e "CC=$CC" -v "$ROOT":/work -w /work \
    husk-dev sh -c '
    set -e
    make clean
    make CC="$CC"
    make rootfs

    # Move PID 1 out of the cgroup namespace root so root controllers can be
    # enabled, then create empty delegated parents for both modes.
    mkdir -p /sys/fs/cgroup/init
    echo 1 > /sys/fs/cgroup/init/cgroup.procs
    printf "+memory +pids +cpu\n" > /sys/fs/cgroup/cgroup.subtree_control
    mkdir -p /sys/fs/cgroup/husk-priv
    printf "+memory +pids +cpu\n" > /sys/fs/cgroup/husk-priv/cgroup.subtree_control
    mkdir -p /sys/fs/cgroup/husk-rootless/user
    printf "+memory +pids +cpu\n" > /sys/fs/cgroup/husk-rootless/cgroup.subtree_control
    mkdir -p /sys/fs/cgroup/husk-denied
    printf "+memory +pids +cpu\n" > /sys/fs/cgroup/husk-denied/cgroup.subtree_control
    chmod 0755 /sys/fs/cgroup/husk-denied

    echo "=== privileged Stage 3/4 ==="
    HUSK_STAGE34_MODE=privileged HUSK_CGROUP_PARENT=/sys/fs/cgroup/husk-priv \
        CC="$CC" /work/tests/stage34.sh

    # Prepare the rootless account and move PID 1 into the delegated subtree.
    groupadd -g 1000 huskprobe 2>/dev/null || true
    useradd -u 1000 -g 1000 -m -s /bin/bash huskprobe 2>/dev/null || true
    chown -R 1000:1000 /sys/fs/cgroup/husk-rootless
    echo 1 > /sys/fs/cgroup/husk-rootless/user/cgroup.procs

    echo "=== rootless Stage 3/4 ==="
    setpriv --reuid=1000 --regid=1000 --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
        env CC="$CC" HUSK_STAGE34_MODE=rootless \
        HUSK_CGROUP_PARENT=/sys/fs/cgroup/husk-rootless \
        HUSK_DENIED_PARENT=/sys/fs/cgroup/husk-denied \
        /work/tests/stage34.sh
'
