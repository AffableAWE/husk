#!/usr/bin/env bash
# Run Stage 5 bridge tests in a disposable privileged container, then verify
# that rootless mode explicitly rejects host bridge networking.
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
    /work/build/rootfs/bin/ip link add huskbr0 type bridge
    /work/build/rootfs/bin/ip link set huskbr0 up
    /work/build/rootfs/bin/ip addr add 10.88.0.1/24 dev huskbr0
    echo 0 > /sys/class/net/huskbr0/bridge/stp_state
    mkdir -p /tmp/husk-stage5-leases

    echo "=== privileged Stage 5 ==="
    HUSK_BRIDGE=huskbr0 HUSK_LEASE_DIR=/tmp/husk-stage5-leases \
        CC="$CC" /work/tests/stage5.sh

    groupadd -g 1000 huskprobe 2>/dev/null || true
    useradd -u 1000 -g 1000 -m -s /bin/bash huskprobe 2>/dev/null || true
    echo "=== rootless bridge rejection ==="
    set +e
    setpriv --reuid=1000 --regid=1000 --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
        /work/husk run --rootless --rootfs /work/build/rootfs \
        --bridge huskbr0 --container-address 10.88.0.9/24 \
        --gateway 10.88.0.1 --lease-dir /tmp/husk-stage5-leases \
        -- /bin/true >/tmp/rootless-bridge.out 2>/tmp/rootless-bridge.err
    rc=$?
    set -e
    if [ "$rc" -eq 125 ] && grep -q "rootless mode supports isolated networking only" /tmp/rootless-bridge.err; then
        echo "ok   rootless bridge request is rejected explicitly (exit 125)"
    else
        echo "FAIL rootless bridge request is rejected explicitly: rc=$rc $(cat /tmp/rootless-bridge.err)"
        exit 1
    fi
'
