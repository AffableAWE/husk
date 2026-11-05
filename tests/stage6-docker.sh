#!/usr/bin/env bash
# Run the 1,000-run Stage 6 campaign in privileged and rootless modes.
set -u
set -o pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
CC=${1:-${CC:-gcc}}
ITERS=${HUSK_CAMPAIGN_ITERS:-1000}

docker run --rm --privileged -e "CC=$CC" -e "ITERS=$ITERS" \
    -v "$ROOT":/work -w /work husk-dev sh -c '
    set -e
    make clean
    make CC="$CC"
    make rootfs
    cc -O2 -g -std=c17 -Wall -Wextra -Werror -Wformat=2 -Wvla         -o build/owned-run tests/owned_run.c
    cc -DHUSK_TEST_HOOKS -Isrc -O2 -g -std=c17 -Wall -Wextra -Werror         -Wformat=2 -Wvla -o build/husk-test         src/main.c src/container.c src/userns.c src/cgroup.c         src/security.c src/network.c src/util.c
    /work/build/rootfs/bin/ip link add huskbr0 type bridge
    /work/build/rootfs/bin/ip link set huskbr0 up
    /work/build/rootfs/bin/ip addr add 10.88.0.1/16 dev huskbr0
    echo 0 > /sys/class/net/huskbr0/bridge/stp_state
    mkdir -p /tmp/husk-stage6-leases

    mkdir -p /sys/fs/cgroup/init
    echo 1 > /sys/fs/cgroup/init/cgroup.procs
    printf "+memory +pids +cpu\n" > /sys/fs/cgroup/cgroup.subtree_control
    mkdir -p /sys/fs/cgroup/husk-priv
    printf "+memory +pids +cpu\n" > /sys/fs/cgroup/husk-priv/cgroup.subtree_control
    mkdir -p /sys/fs/cgroup/husk-rootless/user
    printf "+memory +pids +cpu\n" > /sys/fs/cgroup/husk-rootless/cgroup.subtree_control

    echo "=== privileged Stage 6 ==="
    HUSK_STAGE6_MODE=privileged HUSK_CGROUP_PARENT=/sys/fs/cgroup/husk-priv \
        HUSK_BRIDGE=huskbr0 HUSK_LEASE_DIR=/tmp/husk-stage6-leases \
        HUSK_TEST=/work/build/husk-test HUSK_OWNED_RUN=/work/build/owned-run \
        HUSK_CAMPAIGN_ITERS="$ITERS" CC="$CC" /work/tests/stage6.sh

    groupadd -g 1000 huskprobe 2>/dev/null || true
    useradd -u 1000 -g 1000 -m -s /bin/bash huskprobe 2>/dev/null || true
    chown -R 1000:1000 /sys/fs/cgroup/husk-rootless
    echo 1 > /sys/fs/cgroup/husk-rootless/user/cgroup.procs

    echo "=== rootless Stage 6 ==="
    setpriv --reuid=1000 --regid=1000 --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
        env HUSK_STAGE6_MODE=rootless \
        HUSK_CGROUP_PARENT=/sys/fs/cgroup/husk-rootless \
        HUSK_TEST=/work/build/husk-test HUSK_OWNED_RUN=/work/build/owned-run \
        HUSK_CAMPAIGN_ITERS="$ITERS" CC="$CC" /work/tests/stage6.sh
'
