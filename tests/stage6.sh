#!/usr/bin/env bash
# Stage 6 hardening: ownership-observed fault injection and leak campaign.
# No pattern-based process killing is used; every background launch has a
# verified ownership record managed by tests/owned_run.
set -u
set -o pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1
MODE=${HUSK_STAGE6_MODE:-privileged}
CG=${HUSK_CGROUP_PARENT:-}
SOURCE_ROOTFS=${HUSK_ROOTFS:-"$ROOT/build/rootfs"}
HUSK=${HUSK:-"$ROOT/husk"}
HUSK_TEST=${HUSK_TEST:-"$ROOT/build/husk-test"}
OWNED_RUN=${HUSK_OWNED_RUN:-"$ROOT/build/owned-run"}
BRIDGE=${HUSK_BRIDGE:-huskbr0}
LEASE_DIR=${HUSK_LEASE_DIR:-/tmp/husk-stage6-leases}
ITERS=${HUSK_CAMPAIGN_ITERS:-1000}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/husk-stage6.XXXXXX") || exit 1
ROOTFS="$WORK/rootfs"
BADROOTFS="$WORK/badrootfs"
PASS=0; FAIL=0; SKIP=0
FAILED=()
RECORDS=()
OWNED_PID=""
OWNED_RC=""; OWNED_LEFTOVERS=""; OWNED_LEFTOVER_PIDS=""
REC_OWNER=""; REC_START=""; REC_PGID=""; REC_CHILD=""
LIVE_REC=""; LIVE_OWNER=""; LIVE_START=""; LIVE_CHILD=""; LIVE_OWNED_PID=""; LIVE_CG=""; LIVE_LEASE=""; LIVE_VETH=""

pass() { PASS=$((PASS+1)); printf 'ok   %s\n' "$1"; }
fail() { FAIL=$((FAIL+1)); FAILED+=("$1"); printf 'FAIL %s: %s\n' "$1" "${2:-}"; }
skip() { SKIP=$((SKIP+1)); printf 'skip %s: %s\n' "$1" "$2"; }

proc_starttime() { local s; s=$(cat "/proc/$1/stat" 2>/dev/null) || return 1; s=${s##*) }; set -- $s; printf '%s\n' "${20}"; }
pid_matches() { [ -n "${1:-}" ] && [ -n "${2:-}" ] && [ "$(proc_starttime "$1" 2>/dev/null)" = "$2" ]; }
new_record() { mktemp "$WORK/owned-XXXXXX.record"; }
record_read() {
    local owner start pgid child extra
    REC_OWNER=""; REC_START=""; REC_PGID=""; REC_CHILD=""
    [ -f "$1" ] || return 1
    read -r owner start pgid child extra <"$1" 2>/dev/null || return 1
    [ -z "${extra:-}" ] || return 1
    case "$owner$start$pgid$child" in ''|*[!0-9]*) return 1 ;; esac
    [ "$owner" -gt 1 ] && [ "$start" -gt 0 ] && [ "$child" -gt 1 ] || return 1
    [ "$pgid" -eq "$owner" ] || return 1
    REC_OWNER=$owner; REC_START=$start; REC_PGID=$pgid; REC_CHILD=$child
}
wait_record() {
    local rec=$1 i
    for i in $(seq 1 100); do record_read "$rec" && return 0; sleep 0.05; done
    return 1
}
owned_start() {
    local rec=$1; shift
    "$OWNED_RUN" "$rec" -- "$@" >"$WORK/owned.out" 2>"$WORK/owned.err" &
    OWNED_PID=$!
    RECORDS+=("$rec")
}
owned_wait_status() {
    local rec=$1 limit=${2:-400} i rc left pids
    OWNED_RC=""; OWNED_LEFTOVERS=""; OWNED_LEFTOVER_PIDS=""
    for i in $(seq 1 "$limit"); do
        if [ -s "$rec.status" ]; then
            read -r rc left pids <"$rec.status" 2>/dev/null || true
            case "$rc$left" in ''|*[!0-9]*) return 1 ;; esac
            OWNED_RC=$rc; OWNED_LEFTOVERS=$left; OWNED_LEFTOVER_PIDS=${pids:-}; return 0
        fi
        sleep 0.05
    done
    return 1
}
owned_release() { : >"$1.release"; }
owned_finish() { wait "$2"; local r=$?; rm -f "$1" "$1.status" "$1.release"; return $r; }
check_owned() { # label expected
    [ "${OWNED_RC:-x}" = "$2" ] && pass "$1 (exit $2)" || fail "$1" "expected $2 got ${OWNED_RC:-none}"
    [ "${OWNED_LEFTOVERS:-x}" = 0 ] && pass "$1 observed 0 owned leftovers" || fail "$1" "leftovers=${OWNED_LEFTOVERS:-unknown} pids=${OWNED_LEFTOVER_PIDS:-}"
}
cleanup_record() {
    local rec=$1 i
    [ -f "$rec" ] || { rm -f "$rec.status" "$rec.release"; return 0; }
    record_read "$rec" || { mv -f "$rec" "$rec.unverified" 2>/dev/null || rm -f "$rec"; rm -f "$rec.status" "$rec.release"; return 1; }
    pid_matches "$REC_OWNER" "$REC_START" || { mv -f "$rec" "$rec.unverified" 2>/dev/null || rm -f "$rec"; rm -f "$rec.status" "$rec.release"; return 1; }
    : >"$rec.release"; kill -TERM "$REC_OWNER" 2>/dev/null || true
    for i in $(seq 1 50); do pid_matches "$REC_OWNER" "$REC_START" || break; sleep 0.1; done
    if pid_matches "$REC_OWNER" "$REC_START"; then
        kill -KILL "$REC_OWNER" 2>/dev/null || true
        wait "$REC_OWNER" 2>/dev/null || true
        mv -f "$rec" "$rec.unverified" 2>/dev/null || rm -f "$rec"
        rm -f "$rec.status" "$rec.release"
        return 1
    fi
    wait "$REC_OWNER" 2>/dev/null || true
    rm -f "$rec" "$rec.status" "$rec.release"
    return 0
}
cleanup() {
    local rec
    for rec in "${RECORDS[@]}"; do [ -e "$rec" ] && cleanup_record "$rec" >/dev/null 2>&1 || true; done
    [ -n "${CONTROL_PID:-}" ] && kill -TERM "$CONTROL_PID" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

[ "$(id -u)" -eq 0 ] && [ "$MODE" = privileged ] || [ "$MODE" = rootless ] || { echo "bad mode" >&2; exit 2; }
[ -n "$CG" ] && [ -d "$CG" ] || { echo "cgroup parent missing" >&2; exit 2; }
[ "$MODE" = rootless ] || [ "$(id -u)" -eq 0 ] || { echo "privileged mode needs root" >&2; exit 2; }
[ "$MODE" = privileged ] || [ "$(id -u)" -ne 0 ] || { echo "rootless mode needs non-root" >&2; exit 2; }
[ -x "$HUSK" ] && [ -x "$HUSK_TEST" ] && [ -x "$OWNED_RUN" ] || { echo "runtime/test helper missing" >&2; exit 2; }
if [ "$MODE" = privileged ]; then
    [ -d "$LEASE_DIR" ] && [ -n "$BRIDGE" ] || { echo "bridge/lease prep missing" >&2; exit 2; }
fi
cp -a "$SOURCE_ROOTFS" "$ROOTFS" || exit 1
cp -a "$SOURCE_ROOTFS" "$BADROOTFS" || exit 1
rm -rf "$BADROOTFS/proc"; : >"$BADROOTFS/proc"
chmod -R u+rwX "$ROOTFS" "$BADROOTFS"
RUN_ARGS=()
[ "$MODE" = rootless ] && RUN_ARGS=(--rootless)

bridge_args() { printf '%s\n' --bridge "$BRIDGE" --container-address "$1/16" --gateway 10.88.0.1 --lease-dir "$LEASE_DIR"; }
run_husk() { # rootfs address use_bridge
    local root=$1 addr=$2 useb=$3
    if [ "$useb" = 1 ]; then
        timeout 15 "$HUSK" run "${RUN_ARGS[@]}" --rootfs "$root" --cgroup-parent "$CG" --memory-max 16777216 $(bridge_args "$addr") -- /bin/true
    else
        timeout 15 "$HUSK" run "${RUN_ARGS[@]}" --rootfs "$root" --cgroup-parent "$CG" --memory-max 16777216 -- /bin/true
    fi
}
count_dirs() { find "$CG" -mindepth 1 -maxdepth 1 -type d -name 'husk.*' ! -path "$LIVE_CG" 2>/dev/null | wc -l; }
count_leases() { find "$LEASE_DIR" -maxdepth 1 -type f -name '*.lease' ! -path "$LIVE_LEASE" 2>/dev/null | wc -l; }
count_veths() {
    local n=0 d
    for d in /sys/class/net/hv* /sys/class/net/cv*; do
        [ -e "$d" ] || continue
        [ -n "$LIVE_VETH" ] && [ "$(basename "$d")" = "$LIVE_VETH" ] && continue
        n=$((n+1))
    done
    printf '%s\n' "$n"
}
assert_clean() { # label
    local label=$1 leaks=""
    [ "$(count_dirs)" -eq 0 ] || leaks="$leaks cgroup"
    [ "$MODE" = privileged ] && { [ "$(count_leases)" -eq 0 ] || leaks="$leaks lease"; [ "$(count_veths)" -eq 0 ] || leaks="$leaks veth"; }
    [ -e "$ROOTFS/.oldroot" ] && leaks="$leaks .oldroot"
    grep -Fq " $ROOTFS " /proc/self/mountinfo && leaks="$leaks mount"
    if [ -n "$leaks" ]; then fail "$label" "leaks:$leaks"; return 1; fi
    return 0
}
unrelated_control() { sleep 60; } # this shell's own control process, never in an owned group

echo "== Stage 6 preflight: abrupt parent death and signal cleanup =="
unrelated_control & CONTROL_PID=$!
rec=$(new_record)
owned_start "$rec" "$HUSK" run "${RUN_ARGS[@]}" --rootfs "$ROOTFS" --cgroup-parent "$CG" --memory-max 16777216 -- /bin/sleep 30
if wait_record "$rec"; then
    pass "preflight published an ownership record"
    for i in $(seq 1 100); do LIVE_CG=$(find "$CG" -mindepth 1 -maxdepth 1 -type d -name 'husk.*' | head -1); [ -n "$LIVE_CG" ] && break; sleep 0.05; done
    [ -n "$LIVE_CG" ] && pass "preflight acquired a cgroup" || fail "preflight acquired a cgroup"
    kill -KILL "$REC_CHILD" 2>/dev/null
    if owned_wait_status "$rec"; then
        check_owned "abrupt parent death was observed" 137
        owned_release "$rec"; owned_finish "$rec" "$OWNED_PID" >/dev/null 2>&1
    else fail "abrupt parent death was observed"; cleanup_record "$rec" >/dev/null 2>&1 || true; fi
else fail "preflight published an ownership record"; cleanup_record "$rec" >/dev/null 2>&1 || true; fi
sleep 0.5
[ -n "$LIVE_CG" ] && [ -d "$LIVE_CG" ] && pass "abrupt parent death left the cgroup for recovery" || fail "abrupt parent death left the cgroup for recovery"
timeout 10 "$HUSK" run "${RUN_ARGS[@]}" --rootfs "$ROOTFS" --cgroup-parent "$CG" --memory-max 16777216 -- /bin/true >/dev/null 2>&1
[ "$?" -eq 0 ] && pass "next run recovered the stale cgroup" || fail "next run recovered the stale cgroup"
sleep 0.2
[ ! -d "$LIVE_CG" ] && pass "recovered cgroup is gone" || fail "recovered cgroup is gone"
LIVE_CG=""

rec=$(new_record)
owned_start "$rec" "$HUSK" run "${RUN_ARGS[@]}" --rootfs "$ROOTFS" --cgroup-parent "$CG" --memory-max 16777216 -- /bin/sleep 30
if wait_record "$rec"; then
    kill -TERM "$REC_OWNER" 2>/dev/null
    if owned_wait_status "$rec"; then
        check_owned "SIGTERM invocation" 143
        owned_release "$rec"; owned_finish "$rec" "$OWNED_PID" >/dev/null 2>&1
    else fail "SIGTERM invocation"; cleanup_record "$rec" >/dev/null 2>&1 || true; fi
else fail "SIGTERM invocation"; cleanup_record "$rec" >/dev/null 2>&1 || true; fi
sleep 0.3
assert_clean "signal path" && pass "signal path left no cgroup/mount leak"

echo "== Concurrent healthy container and unrelated control baseline =="
LIVE_ADDR=10.88.3.250
rec=$(new_record)
if [ "$MODE" = privileged ]; then
    owned_start "$rec" "$HUSK" run --rootfs "$ROOTFS" --cgroup-parent "$CG" --memory-max 16777216 $(bridge_args "$LIVE_ADDR") -- /bin/sleep 60
else
    owned_start "$rec" "$HUSK" run "${RUN_ARGS[@]}" --rootfs "$ROOTFS" --cgroup-parent "$CG" --memory-max 16777216 -- /bin/sleep 60
fi
if wait_record "$rec"; then
    LIVE_REC=$rec; LIVE_OWNER=$REC_OWNER; LIVE_START=$REC_START; LIVE_CHILD=$REC_CHILD; LIVE_OWNED_PID=$OWNED_PID
else
    fail "concurrent container published an ownership record"
    cleanup_record "$rec" >/dev/null 2>&1 || true
fi
for i in $(seq 1 200); do LIVE_CG=$(find "$CG" -mindepth 1 -maxdepth 1 -type d -name 'husk.*' | head -1); [ -n "$LIVE_CG" ] && break; sleep 0.05; done
if [ "$MODE" = privileged ]; then
    LIVE_LEASE="$LEASE_DIR/${LIVE_ADDR}_16.lease"
    for i in $(seq 1 100); do [ -s "$LIVE_LEASE" ] && [ "$(wc -w <"$LIVE_LEASE")" -ge 6 ] && break; sleep 0.05; done
    LIVE_VETH=$(awk '{print $6}' "$LIVE_LEASE" 2>/dev/null)
    for i in $(seq 1 100); do [ -n "$LIVE_VETH" ] && [ -e "/sys/class/net/$LIVE_VETH" ] && break; sleep 0.05; done
fi
[ -n "$LIVE_CG" ] && pass "concurrent healthy container has a cgroup" || fail "concurrent healthy container has a cgroup"
if [ "$MODE" = privileged ]; then
    [ -f "$LIVE_LEASE" ] && pass "concurrent healthy container has a lease" || fail "concurrent healthy container has a lease"
    [ -n "$LIVE_VETH" ] && [ -e "/sys/class/net/$LIVE_VETH" ] && pass "concurrent healthy container has a veth" || fail "concurrent healthy container has a veth"
fi
eth_before=$(cat /sys/class/net/eth0/address 2>/dev/null || true)
bridge_before=""
[ "$MODE" = privileged ] && bridge_before=$("$ROOTFS/bin/ip" -4 -o addr show dev "$BRIDGE" 2>/dev/null || true)

echo "== Deterministic failures after resource acquisition =="
fail_phase() { # phase use_bridge label
    local phase=$1 useb=$2 label=$3 rec expected=125
    rec=$(new_record)
    if [ "$useb" = 1 ]; then
        owned_start "$rec" env HUSK_TEST_FAIL_PHASE="$phase" "$HUSK_TEST" run --rootfs "$ROOTFS" --cgroup-parent "$CG" --memory-max 16777216 $(bridge_args 10.88.2.249) -- /bin/true
    else
        owned_start "$rec" env HUSK_TEST_FAIL_PHASE="$phase" "$HUSK_TEST" run "${RUN_ARGS[@]}" --rootfs "$ROOTFS" --cgroup-parent "$CG" --memory-max 16777216 -- /bin/true
    fi
    if wait_record "$rec" && owned_wait_status "$rec"; then
        check_owned "$label" "$expected"
        owned_release "$rec"; owned_finish "$rec" "$OWNED_PID" >/dev/null 2>&1
    else
        fail "$label" "no ownership record/status"
        cleanup_record "$rec" >/dev/null 2>&1 || true
    fi
    assert_clean "$label" && pass "$label left no owned resources"
}
fail_phase after-cgroup-acquire 0 "failure after cgroup acquisition"
if [ "$MODE" = privileged ]; then
    fail_phase after-lease-acquire 1 "failure after lease acquisition"
    fail_phase network-after-veth 1 "failure after veth allocation"
    fail_phase child-before-workload-fork 1 "failure before workload execution"
else
    fail_phase child-before-workload-fork 0 "failure before workload execution"
fi

echo "== 1000-run fault-injection/leak campaign ($MODE) =="
campaign_fail=0
for i in $(seq 1 "$ITERS"); do
    useb=0; root=$ROOTFS
    [ "$MODE" = privileged ] && [ $((i % 5)) -eq 0 ] && useb=1
    if [ $((i % 3)) -eq 0 ]; then root=$BADROOTFS; expected=125; else expected=0; fi
    addr="10.88.2.$(( (i % 200) + 1 ))"
    run_husk "$root" "$addr" "$useb" >"$WORK/run.out" 2>"$WORK/run.err"
    rc=$?
    if [ "$rc" -ne "$expected" ]; then
        campaign_fail=$((campaign_fail+1)); fail "campaign iteration $i exit" "expected $expected got $rc: $(tail -1 "$WORK/run.err")"; break
    fi
    if ! assert_clean "campaign iteration $i"; then campaign_fail=$((campaign_fail+1)); break; fi
    [ $((i % 100)) -eq 0 ] && printf '# campaign %d/%d\n' "$i" "$ITERS"
done
[ "$campaign_fail" -eq 0 ] && pass "campaign completed $ITERS runs without leaks or wrong statuses" || fail "campaign completed $ITERS runs without leaks or wrong statuses" "failures=$campaign_fail"

echo "== Post-campaign assertions before emergency cleanup =="
pid_matches "$LIVE_OWNER" "$LIVE_START" && kill -0 "$LIVE_CHILD" 2>/dev/null && pass "concurrent healthy container survived" || fail "concurrent healthy container survived"
[ -n "$LIVE_CG" ] && [ -d "$LIVE_CG" ] && pass "concurrent cgroup preserved" || fail "concurrent cgroup preserved"
if [ "$MODE" = privileged ]; then
    [ -f "$LIVE_LEASE" ] && pass "concurrent lease preserved" || fail "concurrent lease preserved"
    [ -n "$LIVE_VETH" ] && [ -e "/sys/class/net/$LIVE_VETH" ] && pass "concurrent veth preserved" || fail "concurrent veth preserved"
    [ "$(cat /sys/class/net/eth0/address 2>/dev/null || true)" = "$eth_before" ] && pass "host eth0 preserved" || fail "host eth0 preserved"
    [ "$("$ROOTFS/bin/ip" -4 -o addr show dev "$BRIDGE" 2>/dev/null || true)" = "$bridge_before" ] && pass "bridge preserved" || fail "bridge preserved"
fi
kill -0 "$CONTROL_PID" 2>/dev/null && pass "unrelated control process survived" || fail "unrelated control process survived"
kill -TERM "$LIVE_OWNER" 2>/dev/null
if owned_wait_status "$LIVE_REC"; then
    check_owned "concurrent container stopped" 143
    owned_release "$LIVE_REC"; owned_finish "$LIVE_REC" "$LIVE_OWNED_PID" >/dev/null 2>&1
else
    fail "concurrent container stopped"
    cleanup_record "$LIVE_REC" >/dev/null 2>&1 || true
fi
kill -TERM "$CONTROL_PID" 2>/dev/null; wait "$CONTROL_PID" 2>/dev/null || true
sleep 0.3
LIVE_CG=""; LIVE_LEASE=""; LIVE_VETH=""; LIVE_REC=""; LIVE_OWNER=""; LIVE_START=""; LIVE_CHILD=""; LIVE_OWNED_PID=""
assert_clean "post-cleanup" && pass "campaign cleanup removed owned resources"

echo
echo "passed: $PASS, failed: $FAIL, skipped: $SKIP"
if [ "$FAIL" -ne 0 ]; then printf 'failed checks:\n  - %s\n' "${FAILED[@]}"; exit 1; fi
exit 0
