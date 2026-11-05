#!/usr/bin/env bash
# Measure warm-cache startup and full run/cleanup for the completed feature set.
set -u
set -o pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
CC=${1:-${CC:-gcc}}
ITERS=${PERF_ITERS:-1000}
OUT=${PERF_OUT:-baseline}

docker run --rm --privileged -e "CC=$CC" -e "ITERS=$ITERS" -e "OUT=$OUT" \
    -v "$ROOT":/work -w /work husk-dev sh -c '
    set -e
    make clean
    make CC="$CC"
    make rootfs
    mkdir -p /work/build/evidence/perf
    {
      echo "date=$(date -u +%FT%TZ)"
      echo "kernel=$(uname -a)"
      echo "machine=$(uname -m)"
      echo "nproc=$(nproc)"
      echo "cc=$CC"
      "$CC" --version | head -2
      grep -m1 "model name" /proc/cpuinfo || true
      grep -m1 "BogoMIPS" /proc/cpuinfo || true
    } > "/work/build/evidence/perf/${OUT}-metadata.txt"

    cc -DHUSK_TEST_HOOKS -Isrc -O2 -g -std=c17 -Wall -Wextra -Werror \
        -Wformat=2 -Wvla -o build/husk-perf \
        src/main.c src/container.c src/userns.c src/cgroup.c \
        src/security.c src/network.c src/util.c
    cc -O2 -Wall -Wextra -Werror -o build/perf_runner tests/perf_runner.c

    mkdir -p /sys/fs/cgroup/init
    echo 1 > /sys/fs/cgroup/init/cgroup.procs
    printf "+memory +pids +cpu\n" > /sys/fs/cgroup/cgroup.subtree_control
    mkdir -p /sys/fs/cgroup/husk-perf
    printf "+memory +pids +cpu\n" > /sys/fs/cgroup/husk-perf/cgroup.subtree_control
    mkdir -p /sys/fs/cgroup/husk-rootless/user
    printf "+memory +pids +cpu\n" > /sys/fs/cgroup/husk-rootless/cgroup.subtree_control

    /work/build/rootfs/bin/ip link add huskbr0 type bridge
    /work/build/rootfs/bin/ip link set huskbr0 up
    /work/build/rootfs/bin/ip addr add 10.88.0.1/16 dev huskbr0
    echo 0 > /sys/class/net/huskbr0/bridge/stp_state
    mkdir -p /tmp/husk-perf-leases

    echo "=== warm-up ==="
    ./build/perf_runner 20 ./build/husk-perf run --rootfs /work/build/rootfs \
        --cgroup-parent /sys/fs/cgroup/husk-perf --memory-max 16777216 \
        --rlimit-nofile 256 -- /bin/true >/dev/null
    ./build/perf_runner 20 ./build/husk-perf run --rootfs /work/build/rootfs \
        --cgroup-parent /sys/fs/cgroup/husk-perf --memory-max 16777216 \
        --rlimit-nofile 256 --bridge huskbr0 --container-address 10.88.4.50/16 \
        --gateway 10.88.0.1 --lease-dir /tmp/husk-perf-leases -- /bin/true >/dev/null

    echo "=== privileged isolated (${ITERS}) ==="
    ./build/perf_runner "$ITERS" ./build/husk-perf run --rootfs /work/build/rootfs \
        --cgroup-parent /sys/fs/cgroup/husk-perf --memory-max 16777216 \
        --rlimit-nofile 256 -- /bin/true \
        > "/work/build/evidence/perf/${OUT}-privileged-isolated.csv"

    echo "=== privileged bridge (${ITERS}) ==="
    ./build/perf_runner "$ITERS" ./build/husk-perf run --rootfs /work/build/rootfs \
        --cgroup-parent /sys/fs/cgroup/husk-perf --memory-max 16777216 \
        --rlimit-nofile 256 --bridge huskbr0 --container-address 10.88.4.50/16 \
        --gateway 10.88.0.1 --lease-dir /tmp/husk-perf-leases -- /bin/true \
        > "/work/build/evidence/perf/${OUT}-privileged-bridge.csv"

    groupadd -g 1000 huskprobe 2>/dev/null || true
    useradd -u 1000 -g 1000 -m -s /bin/bash huskprobe 2>/dev/null || true
    rm -rf /tmp/perf-rootfs
    cp -a /work/build/rootfs /tmp/perf-rootfs
    chown -R 1000:1000 /tmp/perf-rootfs
    chown -R 1000:1000 /sys/fs/cgroup/husk-rootless
    echo 1 > /sys/fs/cgroup/husk-rootless/user/cgroup.procs

    echo "=== rootless isolated (${ITERS}) ==="
    setpriv --reuid=1000 --regid=1000 --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
        env HUSK_PERF_FILE= /work/build/perf_runner "$ITERS" \
        /work/build/husk-perf run --rootless --rootfs /tmp/perf-rootfs \
        --cgroup-parent /sys/fs/cgroup/husk-rootless --memory-max 16777216 \
        --rlimit-nofile 256 -- /bin/true \
        > /tmp/perf-rootless.csv
    cp /tmp/perf-rootless.csv "/work/build/evidence/perf/${OUT}-rootless-isolated.csv"

    echo "=== bridge-rootless: unavailable (explicit 125) ==="
    set +e
    setpriv --reuid=1000 --regid=1000 --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
        /work/husk run --rootless --rootfs /tmp/perf-rootfs \
        --bridge huskbr0 --container-address 10.88.4.51/16 \
        --gateway 10.88.0.1 --lease-dir /tmp/husk-perf-leases -- /bin/true \
        > /tmp/perf-rootless-bridge.out 2>&1
    echo "rootless_bridge_rc=$?" >> "/work/build/evidence/perf/${OUT}-metadata.txt"
    cat /tmp/perf-rootless-bridge.out >> "/work/build/evidence/perf/${OUT}-metadata.txt"
'
