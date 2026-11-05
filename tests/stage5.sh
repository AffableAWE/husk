#!/usr/bin/env bash
# Stage 5 bridge networking tests. Run as root in a disposable host netns.
set -u
set -o pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1
HUSK=${HUSK:-"$ROOT/husk"}
SOURCE_ROOTFS=${HUSK_ROOTFS:-"$ROOT/build/rootfs"}
BRIDGE=${HUSK_BRIDGE:-huskbr0}
LEASE_DIR=${HUSK_LEASE_DIR:-/tmp/husk-stage5-leases}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/husk-stage5.XXXXXX") || exit 1
ROOTFS="$WORK/rootfs"
PASS=0; FAIL=0; SKIP=0
FAILED=()

pass() { PASS=$((PASS+1)); printf 'ok   %s\n' "$1"; }
fail() { FAIL=$((FAIL+1)); FAILED+=("$1"); printf 'FAIL %s: %s\n' "$1" "${2:-}"; }
skip() { SKIP=$((SKIP+1)); printf 'skip %s: %s\n' "$1" "$2"; }
expect_rc() { if [ "$3" -eq "$2" ]; then pass "$1 (exit $3)"; else fail "$1" "expected $2 got $3"; fi; }
hroot() { "$HUSK" run --rootfs "$ROOTFS" "$@"; }
bridge_ip() { "$ROOTFS/bin/ip" -4 -o addr show dev "$BRIDGE" 2>/dev/null; }
cleanup() {
    pkill -TERM -f "$HUSK run --rootfs $ROOTFS" 2>/dev/null || true
    sleep 0.2
    pkill -KILL -f "$HUSK run --rootfs $ROOTFS" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

[ "$(id -u)" -eq 0 ] || { echo "error: stage5 needs root" >&2; exit 1; }
[ -d "$SOURCE_ROOTFS" ] || { echo "error: rootfs missing" >&2; exit 1; }
[ -d "$LEASE_DIR" ] || { echo "error: lease dir missing" >&2; exit 1; }
[ -x "$ROOTFS/bin/ip" ] 2>/dev/null || true
cp -a "$SOURCE_ROOTFS" "$ROOTFS" || exit 1
if ! "${CC:-cc}" -static -O2 -Wall -Wextra -Werror -o "$ROOTFS/bin/net_probe" tests/net_probe.c 2>"$WORK/net.err"; then
    echo "error: build net_probe: $(cat "$WORK/net.err")" >&2; exit 1
fi
# Only remove this test's stale leases, never unrelated files.
rm -f "$LEASE_DIR"/*.lease
for d in /sys/class/net/hv* /sys/class/net/cv*; do [ -e "$d" ] && { echo "error: stale veth $d" >&2; exit 1; }; done
eth_before=$(cat /sys/class/net/eth0/address 2>/dev/null || true)
bridge_addr_before=$(bridge_ip)
[ -n "$bridge_addr_before" ] || { echo "error: bridge $BRIDGE missing" >&2; exit 1; }
echo "== Stage 5 environment =="
pass "bridge $BRIDGE exists (root privileged mode)"
pass "lease directory $LEASE_DIR exists"

echo "== Bridge address, loopback, and route =="
out=$(hroot --bridge "$BRIDGE" --container-address 10.88.0.2/24 --gateway 10.88.0.1 --lease-dir "$LEASE_DIR" -- /bin/sh -c 'ip -o addr show eth0; ip route; ip -o link show lo' 2>&1)
rc=$?
expect_rc "bridge container exits 0" 0 "$rc"
printf '%s\n' "$out" | grep -q 'inet 10\.88\.0\.2/24' && pass "container address configured" || fail "container address configured" "$out"
printf '%s\n' "$out" | grep -q 'default via 10\.88\.0\.1 dev eth0' && pass "default route configured" || fail "default route configured" "$out"
printf '%s\n' "$out" | grep -q 'lo: <LOOPBACK,UP' && pass "loopback is up" || fail "loopback is up" "$out"
[ -z "$(ls -A "$LEASE_DIR" 2>/dev/null)" ] && pass "normal exit removed lease" || fail "normal exit removed lease" "$(ls -A "$LEASE_DIR")"
if ls /sys/class/net/hv* >/dev/null 2>&1; then fail "normal exit removed host veth"; else pass "normal exit removed host veth"; fi

echo "== Container-to-container TCP =="
rm -f "$WORK/server.out" "$WORK/client.out"
"$HUSK" run --rootfs "$ROOTFS" --bridge "$BRIDGE" --container-address 10.88.0.2/24 --gateway 10.88.0.1 --lease-dir "$LEASE_DIR" -- /bin/net_probe server 12345 >"$WORK/server.out" 2>"$WORK/server.err" &
spid=$!
for i in $(seq 1 200); do grep -q '^listening$' "$WORK/server.out" 2>/dev/null && break; sleep 0.05; done
timeout 15 "$HUSK" run --rootfs "$ROOTFS" --bridge "$BRIDGE" --container-address 10.88.0.3/24 --gateway 10.88.0.1 --lease-dir "$LEASE_DIR" -- /bin/net_probe client 10.88.0.2 12345 >"$WORK/client.out" 2>"$WORK/client.err"
crc=$?
wait "$spid"; src=$?
expect_rc "TCP client exits 0" 0 "$crc"
expect_rc "TCP server exits 0" 0 "$src"
grep -q 'reply=ok' "$WORK/client.out" && pass "TCP reply crossed the bridge" || fail "TCP reply crossed the bridge" "$(cat "$WORK/client.out")"
grep -q 'server-ok' "$WORK/server.out" && pass "TCP server accepted the connection" || fail "TCP server accepted the connection" "$(cat "$WORK/server.out")"
[ -z "$(ls -A "$LEASE_DIR" 2>/dev/null)" ] && pass "TCP run removed leases" || fail "TCP run removed leases" "$(ls -A "$LEASE_DIR")"
if ls /sys/class/net/hv* >/dev/null 2>&1; then fail "TCP run removed host veths"; else pass "TCP run removed host veths"; fi

echo "== Address uniqueness and concurrency =="
"$HUSK" run --rootfs "$ROOTFS" --bridge "$BRIDGE" --container-address 10.88.0.4/24 --gateway 10.88.0.1 --lease-dir "$LEASE_DIR" -- /bin/sleep 30 >"$WORK/live.out" 2>"$WORK/live.err" &
live=$!
for i in $(seq 1 100); do [ -f "$LEASE_DIR/10.88.0.4_24.lease" ] && break; sleep 0.05; done
[ -f "$LEASE_DIR/10.88.0.4_24.lease" ] && pass "live address has a lease file" || fail "live address has a lease file"
out=$(hroot --bridge "$BRIDGE" --container-address 10.88.0.4/24 --gateway 10.88.0.1 --lease-dir "$LEASE_DIR" -- /bin/true 2>&1)
rc=$?
expect_rc "duplicate live address is rejected" 125 "$rc"
printf '%s\n' "$out" | grep -q 'leased by a live container' && pass "duplicate rejection is actionable" || fail "duplicate rejection is actionable" "$out"
kill -TERM "$live" 2>/dev/null; wait "$live" 2>/dev/null
[ -z "$(ls -A "$LEASE_DIR" 2>/dev/null)" ] && pass "live address cleanup removed lease" || fail "live address cleanup removed lease" "$(ls -A "$LEASE_DIR")"

echo "== Stale-lease recovery after parent SIGKILL =="
"$HUSK" run --rootfs "$ROOTFS" --bridge "$BRIDGE" --container-address 10.88.0.5/24 --gateway 10.88.0.1 --lease-dir "$LEASE_DIR" -- /bin/sleep 30 >"$WORK/stale.out" 2>"$WORK/stale.err" &
stale=$!
for i in $(seq 1 100); do [ -f "$LEASE_DIR/10.88.0.5_24.lease" ] && break; sleep 0.05; done
[ -f "$LEASE_DIR/10.88.0.5_24.lease" ] && pass "stale fixture acquired a lease" || fail "stale fixture acquired a lease"
kill -KILL "$stale" 2>/dev/null; wait "$stale" 2>/dev/null
sleep 1
[ -f "$LEASE_DIR/10.88.0.5_24.lease" ] && pass "crash left a stale lease for recovery" || fail "crash left a stale lease for recovery"
timeout 15 "$HUSK" run --rootfs "$ROOTFS" --bridge "$BRIDGE" --container-address 10.88.0.5/24 --gateway 10.88.0.1 --lease-dir "$LEASE_DIR" -- /bin/true >"$WORK/recover.out" 2>"$WORK/recover.err"
rc=$?
expect_rc "next run recovers the stale address" 0 "$rc"
[ -z "$(ls -A "$LEASE_DIR" 2>/dev/null)" ] && pass "recovery cleanup removed lease" || fail "recovery cleanup removed lease" "$(ls -A "$LEASE_DIR")"

echo "== Invalid network configuration =="
hroot --bridge "$BRIDGE" --container-address not-an-ip --gateway 10.88.0.1 --lease-dir "$LEASE_DIR" -- /bin/true >/dev/null 2>&1; expect_rc "invalid address rejected" 125 $?
hroot --bridge "$BRIDGE" --container-address 10.88.0.6/24 --gateway 10.88.9.1 --lease-dir "$LEASE_DIR" -- /bin/true >/dev/null 2>&1; expect_rc "out-of-subnet gateway rejected" 125 $?
hroot --bridge missing-br0 --container-address 10.88.0.6/24 --gateway 10.88.0.1 --lease-dir "$LEASE_DIR" -- /bin/true >/dev/null 2>&1; expect_rc "missing bridge rejected" 125 $?
hroot --bridge "$BRIDGE" --container-address 10.88.0.6/24 --gateway 10.88.0.1 --lease-dir /no/such/dir -- /bin/true >/dev/null 2>&1; expect_rc "missing lease dir rejected" 125 $?
hroot --bridge "$BRIDGE" -- /bin/true >/dev/null 2>&1; expect_rc "incomplete bridge config rejected" 2 $?

echo "== Preserve unrelated resources =="
[ "$(cat /sys/class/net/eth0/address 2>/dev/null || true)" = "$eth_before" ] && pass "host eth0 unchanged" || fail "host eth0 unchanged"
[ "$(bridge_ip)" = "$bridge_addr_before" ] && pass "bridge address unchanged" || fail "bridge address unchanged"
if ls /sys/class/net/hv* >/dev/null 2>&1; then fail "no host veths remain"; else pass "no host veths remain"; fi
[ -z "$(ls -A "$LEASE_DIR" 2>/dev/null)" ] && pass "no leases remain" || fail "no leases remain" "$(ls -A "$LEASE_DIR")"

echo
echo "passed: $PASS, failed: $FAIL, skipped: $SKIP"
if [ "$FAIL" -ne 0 ]; then printf 'failed checks:\n  - %s\n' "${FAILED[@]}"; exit 1; fi
exit 0
