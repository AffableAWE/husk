#!/usr/bin/env bash
# Run tests/rootless.sh as an ordinary user in a disposable privileged
# container. The container is privileged only so namespaces can be created;
# the actual husk invocations are made by UID 1000 with no capabilities.
#
# Usage:
#   tests/rootless-docker.sh [gcc|clang]
set -u
set -o pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
CC=${1:-${CC:-gcc}}

docker run --rm --privileged -e "CC=$CC" \
    -e "HUSK_TEST_FORCE_STATIC_LOADER=${HUSK_TEST_FORCE_STATIC_LOADER:-}" \
    -v "$ROOT":/work -w /work husk-dev sh -c '
    set -e
    make clean
    make CC="$CC"
    make rootfs
    groupadd -g 1000 huskprobe 2>/dev/null || true
    useradd -u 1000 -g 1000 -m -s /bin/bash huskprobe 2>/dev/null || true
    rm -rf /tmp/rootfs-user
    cp -a /work/build/rootfs /tmp/rootfs-user
    chown -R 1000:1000 /tmp/rootfs-user
    setpriv --reuid=1000 --regid=1000 --clear-groups \
        --inh-caps=-all --ambient-caps=-all --bounding-set=-all \
        env CC="$CC" HUSK_ROOTLESS_ROOTFS=/tmp/rootfs-user \
        /work/tests/rootless.sh
'
