#!/usr/bin/env bash
# Rootless integration tests for husk.
#
# This script MUST run as an ordinary non-root Linux user with no effective
# capabilities. It does not use sudo, setuid binaries, file capabilities, or
# privileged mapping helpers. Prepare the source rootfs and the husk binary
# separately; the script copies the rootfs into a user-owned work directory.
#
# Usage:
#   sudo -u huskuser env HUSK_ROOTLESS_ROOTFS=/path/to/rootfs \
#       tests/rootless.sh
#
# HUSK_ROOTLESS_ROOTFS defaults to build/rootfs.
set -u
set -o pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

HUSK="$ROOT/husk"
SOURCE_ROOTFS=${HUSK_ROOTLESS_ROOTFS:-"$ROOT/build/rootfs"}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/husk-rootless.XXXXXX") || exit 1
ROOTFS="$WORK/rootfs"
OWNED_RUN="$WORK/owned-run"
HUSK_TEST="$WORK/husk-test"
HOOK_DIR="$WORK/hooks"
HOOK_DIR_INSIDE=""
DENY_WRAPPER="$WORK/deny-userns-wrapper"
NOPROC_WRAPPER="$WORK/no-proc-wrapper"
PASS=0
FAIL=0
SKIP=0
FAILED=()
SKIPPED=()
OWNED_PID=""
OUTSIDE_HUSK_PID=""
OUTSIDE_HUSK_START=""
SIGNAL_LOOP_PID=""
HOST_UID=$(id -u)
HOST_GID=$(id -g)
HOST_NAME_BEFORE=""
HOST_MOUNTS_BEFORE=""
HOST_NETNS=""
HOST_MNTNS=""
MARKER=""

fail() {
    FAIL=$((FAIL + 1))
    FAILED+=("$1")
    printf 'FAIL %s: %s\n' "$1" "${2:-}"
}

pass() {
    PASS=$((PASS + 1))
    printf 'ok   %s\n' "$1"
}

skip() {
    SKIP=$((SKIP + 1))
    SKIPPED+=("$1: $2")
    printf 'skip %s: %s\n' "$1" "$2"
}

expect_rc() { # name, expected, actual
    if [ "$3" -eq "$2" ]; then
        pass "$1 (exit $3)"
    else
        fail "$1" "expected exit $2, got $3"
    fi
}

proc_stat() { # pid -> fields after "(comm)"
    local stat

    stat=$(cat "/proc/$1/stat" 2>/dev/null) || return 1
    stat=${stat##*) }
    printf '%s\n' "$stat"
}

proc_starttime() { # pid
    local stat

    stat=$(proc_stat "$1") || return 1
    # shellcheck disable=SC2086
    set -- $stat
    printf '%s\n' "${20}"
}

proc_pgrp() { # pid
    local stat

    stat=$(proc_stat "$1") || return 1
    # shellcheck disable=SC2086
    set -- $stat
    printf '%s\n' "${3}"
}

pid_matches() { # pid, starttime
    [ -n "${1:-}" ] && [ -n "${2:-}" ] &&
        [ "$(proc_starttime "$1" 2>/dev/null)" = "$2" ]
}

pid_in_group() { # pid, pgid
    [ -n "${1:-}" ] && [ -n "${2:-}" ] &&
        [ "$(proc_pgrp "$1" 2>/dev/null)" = "$2" ]
}

group_exists() { # pgid
    [ -n "${1:-}" ] && kill -0 -- "-$1" 2>/dev/null
}

new_record() {
    mktemp "$WORK/owned-XXXXXX.record"
}

record_read() { # record -> REC_OWNER REC_START REC_PGID REC_CHILD
    local owner start pgid child extra

    REC_OWNER=""
    REC_START=""
    REC_PGID=""
    REC_CHILD=""
    [ -f "$1" ] || return 1
    read -r owner start pgid child extra <"$1" 2>/dev/null || return 1
    [ -z "${extra:-}" ] || return 1
    case "$owner" in ''|*[!0-9]*) return 1 ;; esac
    case "$start" in ''|*[!0-9]*) return 1 ;; esac
    case "$pgid" in ''|*[!0-9]*) return 1 ;; esac
    case "$child" in ''|*[!0-9]*) return 1 ;; esac
    [ "$owner" -gt 1 ] && [ "$start" -gt 0 ] && [ "$child" -gt 1 ] ||
        return 1
    [ "$pgid" -eq "$owner" ] || return 1
    REC_OWNER=$owner
    REC_START=$start
    REC_PGID=$pgid
    REC_CHILD=$child
    return 0
}

wait_for_record_child() { # record -> "owner start pgid child"
    local record=$1
    local i owner start pgid child

    for i in $(seq 1 100); do
        if [ -s "$record" ]; then
            read -r owner start pgid child <"$record" 2>/dev/null || true
            if [ -n "${child:-}" ]; then
                printf '%s %s %s %s\n' "$owner" "$start" "$pgid" "$child"
                return 0
            fi
        fi
        sleep 0.05
    done
    return 1
}

owned_start() { # record, command...
    local record=$1

    shift
    "$OWNED_RUN" "$record" -- "$@" &
    OWNED_PID=$!
}

owned_wait_status() { # record [tenths]
    local record=$1
    local limit=${2:-400}
    local i rc leftover pids

    OWNED_RC=""
    OWNED_LEFTOVERS=""
    OWNED_LEFTOVER_PIDS=""
    for i in $(seq 1 "$limit"); do
        if [ -s "$record.status" ]; then
            read -r rc leftover pids <"$record.status" 2>/dev/null || true
            case "$rc" in ''|*[!0-9]*) return 1 ;; esac
            case "$leftover" in ''|*[!0-9]*) return 1 ;; esac
            OWNED_RC=$rc
            OWNED_LEFTOVERS=$leftover
            OWNED_LEFTOVER_PIDS=${pids:-}
            return 0
        fi
        sleep 0.05
    done
    return 1
}

owned_release() { # record
    : >"$1.release"
}

owned_finish() { # record, pid -> supervisor exit status
    local record=$1
    local pid=$2
    local rc

    wait "$pid"
    rc=$?
    rm -f "$record" "$record.status" "$record.release"
    return "$rc"
}

owned_cleanup_verdict() {
    [ -n "${OWNED_LEFTOVERS:-}" ] && [ "$OWNED_LEFTOVERS" -eq 0 ]
}

cleanup_record() { # record
    local record=$1
    local i

    if [ ! -f "$record" ]; then
        rm -f "$record.status" "$record.release"
        return 0
    fi
    if ! record_read "$record"; then
        printf 'cleanup_record: refusing to signal from malformed record %s\n' \
            "$record" >&2
        mv -f "$record" "$record.unverified" 2>/dev/null || rm -f "$record"
        rm -f "$record.status" "$record.release"
        return 1
    fi
    if ! pid_matches "$REC_OWNER" "$REC_START"; then
        printf 'cleanup_record: owner %s (start %s) for group %s is not live and matching; refusing to signal that group\n' \
            "$REC_OWNER" "$REC_START" "$REC_PGID" >&2
        mv -f "$record" "$record.unverified" 2>/dev/null || rm -f "$record"
        rm -f "$record.status" "$record.release"
        return 1
    fi

    : >"$record.release"
    kill -TERM "$REC_OWNER" 2>/dev/null || true
    for i in $(seq 1 50); do
        pid_matches "$REC_OWNER" "$REC_START" || break
        sleep 0.1
    done
    if pid_matches "$REC_OWNER" "$REC_START"; then
        kill -KILL "$REC_OWNER" 2>/dev/null || true
        wait "$REC_OWNER" 2>/dev/null || true
        mv -f "$record" "$record.unverified" 2>/dev/null || rm -f "$record"
        rm -f "$record.status" "$record.release"
        return 1
    fi
    wait "$REC_OWNER" 2>/dev/null || true
    rm -f "$record" "$record.status" "$record.release"
    return 0
}

wait_group_gone() { # pgid
    local i

    [ -n "${1:-}" ] || return 1
    for i in $(seq 1 50); do
        group_exists "$1" || return 0
        sleep 0.1
    done
    return 1
}

group_others() { # pgid, owner -> pids of non-owner group members
    local pid pgrp out=""

    for pid in /proc/[0-9]*; do
        pid=${pid#/proc/}
        [ "$pid" = "$2" ] && continue
        pgrp=$(proc_pgrp "$pid" 2>/dev/null) || continue
        [ "$pgrp" = "$1" ] && out="$out $pid"
    done
    printf '%s\n' "${out# }"
}

owned_start_watchdog() { # seconds, out, err, record, command...
    local seconds=$1
    local out=$2
    local err=$3
    local record=$4

    shift 4
    timeout -k 5 "$seconds" "$OWNED_RUN" "$record" -- "$@" >"$out" 2>"$err" &
    OWNED_PID=$!
}

clear_hooks() {
    rm -f "$HOOK_DIR"/* "$HOOK_DIR_INSIDE"/* 2>/dev/null || true
}

hook_exists() { # phase
    [ -e "$HOOK_DIR/$1" ] || [ -e "$HOOK_DIR_INSIDE/$1" ]
}

wait_for_hook() { # phase [tenths]
    local phase=$1
    local limit=${2:-400}
    local i

    for i in $(seq 1 "$limit"); do
        hook_exists "$phase" && return 0
        sleep 0.05
    done
    return 1
}

hook_text() { # phase
    if [ -e "$HOOK_DIR/$1" ]; then
        cat "$HOOK_DIR/$1"
    else
        cat "$HOOK_DIR_INSIDE/$1"
    fi
}

capture_hook() { # phase, destination basename
    if [ -e "$HOOK_DIR/$1" ]; then
        cp "$HOOK_DIR/$1" "$WORK/$2" 2>/dev/null || true
    elif [ -e "$HOOK_DIR_INSIDE/$1" ]; then
        cp "$HOOK_DIR_INSIDE/$1" "$WORK/$2" 2>/dev/null || true
    fi
}

start_interrupt_loop() { # pid
    local pid=$1
    local start

    start=$(proc_starttime "$pid" 2>/dev/null || true)
    [ -n "$start" ] || return 1
    (
        for _ in $(seq 1 200); do
            pid_matches "$pid" "$start" || break
            kill -USR1 "$pid" 2>/dev/null || break
            sleep 0.2
        done
    ) &
    SIGNAL_LOOP_PID=$!
    return 0
}

stop_interrupt_loop() {
    if [ -n "${SIGNAL_LOOP_PID:-}" ]; then
        kill "$SIGNAL_LOOP_PID" 2>/dev/null || true
        wait "$SIGNAL_LOOP_PID" 2>/dev/null || true
        SIGNAL_LOOP_PID=""
    fi
}

release_hook() { # phase
    : >"$HOOK_DIR/$1.release"
    : >"$HOOK_DIR_INSIDE/$1.release" 2>/dev/null || true
}

clear_workload() {
    rm -f "$ROOTFS/workload-ran"
}

workload_absent() {
    [ ! -e "$ROOTFS/workload-ran" ]
}

check_no_owned_leftovers() { # name
    if owned_cleanup_verdict; then
        pass "$1 (leftovers=$OWNED_LEFTOVERS)"
    else
        fail "$1" "leftovers=${OWNED_LEFTOVERS:-unknown} pids=${OWNED_LEFTOVER_PIDS:-unknown}"
    fi
}

cleanup() {
    local record

    for record in "$WORK"/owned-*.record; do
        [ -e "$record" ] && cleanup_record "$record" >/dev/null 2>&1 || true
    done
    if [ -n "${OUTSIDE_HUSK_PID:-}" ] &&
       pid_matches "$OUTSIDE_HUSK_PID" "$OUTSIDE_HUSK_START"; then
        kill -TERM "$OUTSIDE_HUSK_PID" 2>/dev/null || true
        wait "$OUTSIDE_HUSK_PID" 2>/dev/null || true
    fi
    stop_interrupt_loop
    rm -rf "$WORK"
}

trap cleanup EXIT

hroot() {
    "$HUSK" run --rootless --rootfs "$ROOTFS" "$@"
}

if [ "$HOST_UID" -eq 0 ]; then
    echo "error: rootless tests must run as a non-root user" >&2
    exit 1
fi
if [ ! -x "$HUSK" ]; then
    echo "error: $HUSK is not executable (run make)" >&2
    exit 1
fi
if [ ! -d "$SOURCE_ROOTFS" ]; then
    echo "error: rootfs '$SOURCE_ROOTFS' does not exist" >&2
    exit 1
fi

# Work only on a user-owned copy. The supplied rootfs is trusted input and is
# never mutated by this script.
cp -a "$SOURCE_ROOTFS" "$ROOTFS" || exit 1
chmod -R u+rwX "$ROOTFS" || exit 1

# Hooks write to the same absolute path from outside and, after pivot_root,
# inside the copied rootfs. The parent uses the host directory; the child uses
# the path under the copied rootfs.
HOOK_DIR_INSIDE="$ROOTFS$HOOK_DIR"
mkdir -p "$HOOK_DIR" "$HOOK_DIR_INSIDE" || exit 1
chmod 0755 "$HOOK_DIR" "$HOOK_DIR_INSIDE" || exit 1

if ! "${CC:-cc}" -O2 -g -std=c17 -Wall -Wextra -Werror -Wformat=2 -Wvla \
        -o "$OWNED_RUN" "$ROOT/tests/owned_run.c" \
        2>"$WORK/owned-run-build.err"; then
    echo "error: cannot build tests/owned_run.c: $(cat "$WORK/owned-run-build.err")" >&2
    exit 1
fi
if ! "${CC:-cc}" -O2 -g -std=c17 -Wall -Wextra -Werror -Wformat=2 -Wvla \
        -o "$DENY_WRAPPER" "$ROOT/tests/deny_userns_wrapper.c" \
        2>"$WORK/deny-build.err"; then
    echo "error: cannot build deny_userns_wrapper.c: $(cat "$WORK/deny-build.err")" >&2
    exit 1
fi
if ! "${CC:-cc}" -O2 -g -std=c17 -Wall -Wextra -Werror -Wformat=2 -Wvla \
        -o "$NOPROC_WRAPPER" "$ROOT/tests/no_proc_rootless_wrapper.c" \
        2>"$WORK/noproc-build.err"; then
    echo "error: cannot build no_proc_rootless_wrapper.c: $(cat "$WORK/noproc-build.err")" >&2
    exit 1
fi
if ! "${CC:-cc}" -DHUSK_TEST_HOOKS -I"$ROOT/src" -O2 -g -std=c17 \
        -Wall -Wextra -Werror -Wformat=2 -Wvla \
        -o "$HUSK_TEST" "$ROOT/src/main.c" "$ROOT/src/container.c" \
        "$ROOT/src/userns.c" "$ROOT/src/cgroup.c" "$ROOT/src/security.c" \
        "$ROOT/src/network.c" "$ROOT/src/util.c" \
        2>"$WORK/husk-test-build.err"; then
    echo "error: cannot build handshake test binary: $(cat "$WORK/husk-test-build.err")" >&2
    exit 1
fi

echo "== Caller identity and host capabilities =="

IDENTITY_BEFORE="$WORK/identity-before.txt"
{
    echo "id: $(id)"
    echo "uid: $HOST_UID"
    echo "gid: $HOST_GID"
    grep -E '^(Uid|Gid|CapInh|CapPrm|CapEff|CapBnd|CapAmb|NoNewPrivs|Seccomp):' \
        /proc/self/status
    echo "uid_map:"
    cat /proc/self/uid_map
    echo "gid_map:"
    cat /proc/self/gid_map
} >"$IDENTITY_BEFORE" 2>&1 || true

CAP_EFF=$(awk '/^CapEff:/{print $2}' /proc/self/status 2>/dev/null || true)
CAP_PRM=$(awk '/^CapPrm:/{print $2}' /proc/self/status 2>/dev/null || true)

if [ "$HOST_UID" -ne 0 ]; then
    pass "caller has a nonzero UID ($HOST_UID)"
else
    fail "caller has a nonzero UID"
fi
if [ "$HOST_GID" -ne 0 ]; then
    pass "caller has a nonzero primary GID ($HOST_GID)"
else
    fail "caller has a nonzero primary GID"
fi
case "${CAP_EFF:-}" in
    ''|*[!0]*) fail "caller has no effective host capabilities" \
                    "CapEff=${CAP_EFF:-unknown}" ;;
    *) pass "caller has no effective host capabilities (CapEff=$CAP_EFF)" ;;
esac
case "${CAP_PRM:-}" in
    ''|*[!0]*) fail "caller has no permitted host capabilities" \
                    "CapPrm=${CAP_PRM:-unknown}" ;;
    *) pass "caller has no permitted host capabilities (CapPrm=$CAP_PRM)" ;;
esac

echo "== Rootless availability =="

hroot -- /bin/true >"$WORK/availability.out" 2>&1
availability_rc=$?
expect_rc "rootless /bin/true" 0 "$availability_rc"
if [ "$availability_rc" -ne 0 ]; then
    echo "BLOCKED: the initial rootless run failed:" >&2
    cat "$WORK/availability.out" >&2
    echo "passed: $PASS, failed: $FAIL, skipped: $SKIP"
    exit 2
fi

echo "== Mode selection guard =="

"$HUSK" run --rootfs "$ROOTFS" -- /bin/true >"$WORK/privmode.out" 2>&1
privmode_rc=$?
expect_rc "non-root invocation without --rootless is refused" 125 "$privmode_rc"
grep -q "requires root" "$WORK/privmode.out" &&
    pass "privileged mode reports the root requirement" ||
    fail "privileged mode reports the root requirement" \
         "got '$(cat "$WORK/privmode.out")'"
grep -q -- "--rootless" "$WORK/privmode.out" &&
    pass "privileged-mode refusal points at --rootless" ||
    fail "privileged-mode refusal points at --rootless" \
         "got '$(cat "$WORK/privmode.out")'"

echo "== Basic rootless execution and status propagation =="

out=$(hroot -- /bin/sh -c 'echo rootless-ok' 2>&1)
rc=$?
expect_rc "noninteractive rootless command exits 0" 0 "$rc"
if [ "$out" = "rootless-ok" ]; then
    pass "rootless output is correct"
else
    fail "rootless output is correct" "got '$out'"
fi

"$HUSK" run --rootless --rootfs="$ROOTFS" -- /bin/true
expect_rc "--rootless with --rootfs=DIR works" 0 $?

hroot -- /bin/sh -c 'exit 7' >/dev/null 2>&1
expect_rc "rootless workload exit 7 propagates" 7 $?

hroot -- /bin/false >/dev/null 2>&1
expect_rc "rootless workload exit 1 propagates" 1 $?

hroot -- /bin/sh -c 'kill -TERM $$' >/dev/null 2>&1
expect_rc "rootless workload killed by SIGTERM maps to 143" 143 $?

echo "== UID/GID mapping and caller identity =="

IDENTITY_INSIDE="$WORK/identity-inside.txt"
hroot -- /bin/sh -c '
    echo "uid=$(id -u)"
    echo "gid=$(id -g)"
    echo "groups=$(id -G)"
    echo "uid_map=$(cat /proc/self/uid_map)"
    echo "gid_map=$(cat /proc/self/gid_map)"
    echo "setgroups=$(cat /proc/self/setgroups)"
    echo "cap_inh=$(awk "/^CapInh:/{print \$2}" /proc/self/status)"
    echo "cap_prm=$(awk "/^CapPrm:/{print \$2}" /proc/self/status)"
    echo "cap_eff=$(awk "/^CapEff:/{print \$2}" /proc/self/status)"
    echo "cap_bnd=$(awk "/^CapBnd:/{print \$2}" /proc/self/status)"
    echo "cap_amb=$(awk "/^CapAmb:/{print \$2}" /proc/self/status)"
    echo "no_new_privs=$(awk "/^NoNewPrivs:/{print \$2}" /proc/self/status)"
    echo "seccomp=$(awk "/^Seccomp:/{print \$2}" /proc/self/status)"
' >"$IDENTITY_INSIDE" 2>&1
identity_rc=$?
expect_rc "inside identity probe exits 0" 0 "$identity_rc"

if [ -s "$IDENTITY_INSIDE" ]; then
    inside_uid=$(sed -n 's/^uid=//p' "$IDENTITY_INSIDE")
    inside_gid=$(sed -n 's/^gid=//p' "$IDENTITY_INSIDE")
    inside_uid_map=$(sed -n 's/^uid_map=//p' "$IDENTITY_INSIDE")
    inside_gid_map=$(sed -n 's/^gid_map=//p' "$IDENTITY_INSIDE")
    inside_setgroups=$(sed -n 's/^setgroups=//p' "$IDENTITY_INSIDE")
    inside_cap_inh=$(sed -n 's/^cap_inh=//p' "$IDENTITY_INSIDE")
    inside_cap_prm=$(sed -n 's/^cap_prm=//p' "$IDENTITY_INSIDE")
    inside_cap_eff=$(sed -n 's/^cap_eff=//p' "$IDENTITY_INSIDE")
    inside_cap_bnd=$(sed -n 's/^cap_bnd=//p' "$IDENTITY_INSIDE")
    inside_cap_amb=$(sed -n 's/^cap_amb=//p' "$IDENTITY_INSIDE")
    inside_nnp=$(sed -n 's/^no_new_privs=//p' "$IDENTITY_INSIDE")
    inside_seccomp=$(sed -n 's/^seccomp=//p' "$IDENTITY_INSIDE")

    [ "$inside_uid" = "0" ] && pass "container UID is 0" ||
        fail "container UID is 0" "got '$inside_uid'"
    [ "$inside_gid" = "0" ] && pass "container GID is 0" ||
        fail "container GID is 0" "got '$inside_gid'"
    read -r u_in u_out u_count <<<"$inside_uid_map"
    if [ "${u_in:-x}" = "0" ] && [ "${u_out:-x}" = "$HOST_UID" ] &&
       [ "${u_count:-x}" = "1" ]; then
        pass "uid_map maps inside 0 to caller $HOST_UID for one ID"
    else
        fail "uid_map maps inside 0 to caller $HOST_UID for one ID" \
             "got '$inside_uid_map'"
    fi
    read -r g_in g_out g_count <<<"$inside_gid_map"
    if [ "${g_in:-x}" = "0" ] && [ "${g_out:-x}" = "$HOST_GID" ] &&
       [ "${g_count:-x}" = "1" ]; then
        pass "gid_map maps inside 0 to caller $HOST_GID for one ID"
    else
        fail "gid_map maps inside 0 to caller $HOST_GID for one ID" \
             "got '$inside_gid_map'"
    fi
    [ "$inside_setgroups" = "deny" ] &&
        pass "setgroups is denied in the user namespace" ||
        fail "setgroups is denied in the user namespace" \
             "got '$inside_setgroups'"
    case "${inside_cap_inh:-x}${inside_cap_prm:-x}${inside_cap_eff:-x}${inside_cap_bnd:-x}${inside_cap_amb:-x}" in
        *[!0]*) fail "workload capability sets are all empty" \
                     "Inh=$inside_cap_inh Prm=$inside_cap_prm Eff=$inside_cap_eff Bnd=$inside_cap_bnd Amb=$inside_cap_amb" ;;
        *) pass "workload capability sets are all empty" ;;
    esac
    [ "$inside_nnp" = "1" ] &&
        pass "workload has no_new_privs=1" ||
        fail "workload has no_new_privs=1" "got '$inside_nnp'"
    [ "$inside_seccomp" = "2" ] &&
        pass "workload has seccomp filter mode 2" ||
        fail "workload has seccomp filter mode 2" "got '$inside_seccomp'"
else
    fail "inside identity probe produced output"
fi

# Observe the husk parent and the container init from the host side, while a
# rootless sleep keeps them alive.
"$HUSK" run --rootless --rootfs "$ROOTFS" -- /bin/sleep 30 >/dev/null 2>&1 &
outside_husk_pid=$!
OUTSIDE_HUSK_PID=$outside_husk_pid
OUTSIDE_HUSK_START=$(proc_starttime "$outside_husk_pid" 2>/dev/null || true)
outside_init_pid=""
for _ in $(seq 1 100); do
    outside_init_pid=$(pgrep -P "$outside_husk_pid" -x husk 2>/dev/null |
                           head -n 1 || true)
    [ -n "$outside_init_pid" ] && break
    sleep 0.05
done

IDENTITY_OUTSIDE="$WORK/identity-outside.txt"
if [ -n "$outside_init_pid" ]; then
    {
        echo "husk_pid=$outside_husk_pid"
        echo "init_pid=$outside_init_pid"
        grep -E '^(Uid|Gid|CapEff|CapPrm):' "/proc/$outside_husk_pid/status"
        echo "init_status:"
        grep -E '^(Uid|Gid|CapEff|CapPrm):' "/proc/$outside_init_pid/status"
        echo "init_uid_map:"
        cat "/proc/$outside_init_pid/uid_map"
        echo "init_gid_map:"
        cat "/proc/$outside_init_pid/gid_map"
        echo "init_setgroups:"
        cat "/proc/$outside_init_pid/setgroups"
    } >"$IDENTITY_OUTSIDE" 2>&1 || true

    parent_uid=$(awk '/^Uid:/{print $2}' "/proc/$outside_husk_pid/status" \
                     2>/dev/null || true)
    init_uid=$(awk '/^Uid:/{print $2}' "/proc/$outside_init_pid/status" \
                   2>/dev/null || true)
    init_gid=$(awk '/^Gid:/{print $2}' "/proc/$outside_init_pid/status" \
                   2>/dev/null || true)
    init_uid_in=$(awk 'NR==1{print $1}' "/proc/$outside_init_pid/uid_map" \
                      2>/dev/null || true)
    init_uid_out=$(awk 'NR==1{print $2}' "/proc/$outside_init_pid/uid_map" \
                       2>/dev/null || true)
    init_uid_count=$(awk 'NR==1{print $3}' "/proc/$outside_init_pid/uid_map" \
                         2>/dev/null || true)
    init_gid_in=$(awk 'NR==1{print $1}' "/proc/$outside_init_pid/gid_map" \
                      2>/dev/null || true)
    init_gid_out=$(awk 'NR==1{print $2}' "/proc/$outside_init_pid/gid_map" \
                       2>/dev/null || true)
    init_gid_count=$(awk 'NR==1{print $3}' "/proc/$outside_init_pid/gid_map" \
                         2>/dev/null || true)
    init_setgroups=$(cat "/proc/$outside_init_pid/setgroups" 2>/dev/null ||
                         true)

    [ "$parent_uid" = "$HOST_UID" ] &&
        pass "husk parent is the ordinary caller UID from outside" ||
        fail "husk parent is the ordinary caller UID from outside" \
             "got '$parent_uid'"
    [ "$init_uid" = "$HOST_UID" ] && [ "$init_gid" = "$HOST_GID" ] &&
        pass "container init has ordinary caller UID/GID from outside" ||
        fail "container init has ordinary caller UID/GID from outside" \
             "uid='$init_uid' gid='$init_gid'"
    if [ "$init_uid_in" = "0" ] && [ "$init_uid_out" = "$HOST_UID" ] &&
       [ "$init_uid_count" = "1" ]; then
        pass "outside uid_map confirms inside 0 maps to caller $HOST_UID"
    else
        fail "outside uid_map confirms inside 0 maps to caller $HOST_UID" \
             "in='$init_uid_in' out='$init_uid_out' count='$init_uid_count'"
    fi
    if [ "$init_gid_in" = "0" ] && [ "$init_gid_out" = "$HOST_GID" ] &&
       [ "$init_gid_count" = "1" ]; then
        pass "outside gid_map confirms inside 0 maps to caller $HOST_GID"
    else
        fail "outside gid_map confirms inside 0 maps to caller $HOST_GID" \
             "in='$init_gid_in' out='$init_gid_out' count='$init_gid_count'"
    fi
    [ "$init_setgroups" = "deny" ] &&
        pass "outside setgroups file says deny" ||
        fail "outside setgroups file says deny" "got '$init_setgroups'"
else
    fail "rootless container init is visible from outside"
    cat "$IDENTITY_OUTSIDE" 2>/dev/null || true
fi

kill -TERM "$outside_husk_pid" 2>/dev/null || true
wait "$outside_husk_pid" 2>/dev/null || true
OUTSIDE_HUSK_PID=""
OUTSIDE_HUSK_START=""
SIGNAL_LOOP_PID=""

echo "== Hostname, PID, mount, and filesystem isolation =="

HOST_NAME_BEFORE=$(hostname)
HOST_MOUNTS_BEFORE=$(sha256sum </proc/self/mountinfo)
HOST_MNTNS=$(readlink /proc/self/ns/mnt 2>/dev/null || true)

out=$(hroot --hostname rootless-husk -- /bin/sh -c \
    'hostname; uname -n; echo pid=$$; cat /proc/1/comm' 2>&1)
rc=$?
expect_rc "hostname/PID probe exits 0" 0 "$rc"
if printf '%s\n' "$out" | sed -n '1p' | grep -qx 'rootless-husk' &&
   printf '%s\n' "$out" | sed -n '2p' | grep -qx 'rootless-husk'; then
    pass "rootless container hostname is isolated"
else
    fail "rootless container hostname is isolated" "got '$out'"
fi
if printf '%s\n' "$out" | sed -n '3p' | grep -qx 'pid=2'; then
    pass "rootless workload runs as PID 2 with husk as PID 1"
else
    fail "rootless workload runs as PID 2 with husk as PID 1" "got '$out'"
fi
if printf '%s\n' "$out" | sed -n '4p' | grep -qx 'husk'; then
    pass "rootless container init is husk"
else
    fail "rootless container init is husk" "got '$out'"
fi

container_mntns=$(hroot -- /bin/readlink /proc/self/ns/mnt 2>&1)
if [ -n "$HOST_MNTNS" ] && [ -n "$container_mntns" ] &&
   [ "$container_mntns" != "$HOST_MNTNS" ]; then
    pass "rootless mount namespace differs from the host"
else
    fail "rootless mount namespace differs from the host" \
         "host='$HOST_MNTNS' container='$container_mntns'"
fi

MARKER="$WORK/host-marker"
printf 'rootless-host-marker-%s\n' "$$" >"$MARKER"
if [ -f "$MARKER" ]; then
    pass "host marker exists outside the rootfs"
else
    fail "host marker exists outside the rootfs"
fi
out=$(hroot -- /bin/sh -c 'test ! -e "$1" && echo absent' sh "$MARKER" 2>&1)
rc=$?
expect_rc "marker absence probe exits 0" 0 "$rc"
[ "$out" = "absent" ] && pass "host marker is absent inside rootless container" ||
    fail "host marker is absent inside rootless container" "got '$out'"
if test ! -e "$MARKER"; then
    fail "negative control: marker is visible on the host"
else
    pass "negative control: marker is visible on the host"
fi
hroot -- /bin/cat "$MARKER" >/dev/null 2>&1
[ $? -ne 0 ] && pass "reading the host marker path inside fails" ||
    fail "reading the host marker path inside fails"

out=$(hroot -- /bin/sh -c \
    'test -d /bin && test -f /etc/passwd && echo rootfs-ok' 2>&1)
[ "$out" = "rootfs-ok" ] && pass "rootless root is the supplied rootfs" ||
    fail "rootless root is the supplied rootfs" "got '$out'"

HOST_NAME_AFTER=$(hostname)
HOST_MOUNTS_AFTER=$(sha256sum </proc/self/mountinfo)
[ "$HOST_NAME_BEFORE" = "$HOST_NAME_AFTER" ] &&
    pass "host hostname is unchanged" ||
    fail "host hostname is unchanged" "$HOST_NAME_BEFORE -> $HOST_NAME_AFTER"
[ "$HOST_MOUNTS_BEFORE" = "$HOST_MOUNTS_AFTER" ] &&
    pass "host mount state is unchanged" ||
    fail "host mount state is unchanged"
if mountpoint -q "$ROOTFS/proc" 2>/dev/null; then
    fail "rootfs/proc is not mounted on the host"
else
    pass "rootfs/proc is not mounted on the host"
fi

echo "== Network namespace isolation =="

dev=$(hroot -- /bin/cat /proc/net/dev 2>&1)
dev_rc=$?
links=$(hroot -- /bin/ip -o link 2>&1)
links_rc=$?
addrs=$(hroot -- /bin/ip -o addr 2>&1)
addrs_rc=$?
routes=$(hroot -- /bin/ip route 2>&1)
routes_rc=$?
expect_rc "/proc/net/dev collection exits 0" 0 "$dev_rc"
expect_rc "ip -o link collection exits 0" 0 "$links_rc"
expect_rc "ip -o addr collection exits 0" 0 "$addrs_rc"
expect_rc "ip route collection exits 0" 0 "$routes_rc"

if [ "$dev_rc" -eq 0 ] && [ "$links_rc" -eq 0 ] &&
   [ "$addrs_rc" -eq 0 ] && [ "$routes_rc" -eq 0 ]; then
    printf '%s\n' "$links" | grep -q ': lo:' &&
        pass "rootless network namespace contains loopback" ||
        fail "rootless network namespace contains loopback" "links='$links'"
    printf '%s\n' "$links" | grep -q ': lo:.*<LOOPBACK' &&
        pass "rootless loopback has LOOPBACK flag" ||
        fail "rootless loopback has LOOPBACK flag" "links='$links'"
    printf '%s\n' "$links" | grep -q ': lo:.*UP' &&
        fail "rootless loopback is down (no connectivity)" "links='$links'" ||
        pass "rootless loopback is down (no connectivity)"
    nonlo_up=$(printf '%s\n' "$links" | awk -F': ' '
        { name=$2; sub(/@.*/, "", name);
          if (name != "lo" && $0 ~ /<[^>]*UP[^>]*>/) print name }')
    [ -z "$nonlo_up" ] && pass "no non-loopback interface is up in rootless mode" ||
        fail "no non-loopback interface is up in rootless mode" "up: $nonlo_up"
    external_names=$(printf '%s\n' "$links" | awk -F': ' '
        { name=$2; sub(/@.*/, "", name);
          if (name ~ /^(eth|wlan|enp|eno|ens|enx|wwan|wwp|bond|docker|veth)/)
              print name }')
    [ -z "$external_names" ] &&
        pass "no external interface names are present in rootless mode" ||
        fail "no external interface names are present in rootless mode" \
             "found: $external_names"
    [ -z "$addrs" ] && pass "no addresses are configured in rootless mode" ||
        fail "no addresses are configured in rootless mode" "addrs='$addrs'"
    [ -z "$routes" ] && pass "no routes are configured in rootless mode" ||
        fail "no routes are configured in rootless mode" "routes='$routes'"
else
    fail "network assertions skipped because a probe command failed" \
         "dev_rc=$dev_rc links_rc=$links_rc addrs_rc=$addrs_rc routes_rc=$routes_rc"
fi

HOST_NETNS=$(readlink /proc/self/ns/net 2>/dev/null || true)
container_netns=$(hroot -- /bin/readlink /proc/self/ns/net 2>&1)
if [ -n "$HOST_NETNS" ] && [ -n "$container_netns" ] &&
   [ "$container_netns" != "$HOST_NETNS" ]; then
    pass "rootless network namespace differs from the host"
else
    fail "rootless network namespace differs from the host" \
         "host='$HOST_NETNS' container='$container_netns'"
fi

hroot -- /bin/ping -c 1 -W 1 192.0.2.1 >/dev/null 2>&1
ping_rc=$?
[ "$ping_rc" -eq 1 ] &&
    pass "rootless connectivity probe fails with rc 1" ||
    fail "rootless connectivity probe fails with rc 1" "got rc $ping_rc"

echo "== Rootless executable resolution =="

if ! "${CC:-cc}" -static -O2 -Wall -Wextra -Werror \
        -o "$ROOTFS/bin/exec-probe-target" "$ROOT/tests/exec_probe.c" \
        2>"$WORK/exec-probe-build.err"; then
    fail "build static rootless exec probe" \
         "$(cat "$WORK/exec-probe-build.err")"
else
    ln -sf /bin/exec-probe-target "$ROOTFS/bin/abs-probe"
    printf '#!/bin/sh\necho relative-ok\n' >"$ROOTFS/bin/rel-probe"
    chmod 0755 "$ROOTFS/bin/rel-probe"
    mkdir -p "$ROOTFS/usr/local/bin" "$ROOTFS/usr/bin"
    cp "$ROOTFS/bin/exec-probe-target" "$ROOTFS/usr/bin/path-probe"
    chmod 0755 "$ROOTFS/usr/bin/path-probe"
    printf '#!/bin/sh\necho decoy-should-not-run\n' \
        >"$ROOTFS/usr/local/bin/path-probe"
    chmod 0644 "$ROOTFS/usr/local/bin/path-probe"
    printf '#!/bin/sh\necho noexec-should-not-run\n' \
        >"$ROOTFS/usr/local/bin/noexec-only"
    chmod 0644 "$ROOTFS/usr/local/bin/noexec-only"

    out=$(hroot -- /bin/exec-probe-target 2>&1)
    rc=$?
    expect_rc "rootless absolute path exits 0" 0 "$rc"
    [ "$out" = "exec-probe-ok" ] &&
        pass "rootless absolute path executes the probe" ||
        fail "rootless absolute path executes the probe" "got '$out'"

    out=$(hroot -- /bin/abs-probe 2>&1)
    rc=$?
    expect_rc "rootless absolute symlink exits 0" 0 "$rc"
    [ "$out" = "exec-probe-ok" ] &&
        pass "rootless absolute symlink resolves inside rootfs" ||
        fail "rootless absolute symlink resolves inside rootfs" "got '$out'"

    out=$(hroot -- usr/bin/path-probe 2>&1)
    rc=$?
    expect_rc "rootless relative path exits 0" 0 "$rc"
    [ "$out" = "exec-probe-ok" ] &&
        pass "rootless relative path resolves from container /" ||
        fail "rootless relative path resolves from container /" "got '$out'"

    out=$(hroot -- path-probe 2>&1)
    rc=$?
    expect_rc "rootless PATH search skips a non-executable candidate" 0 "$rc"
    [ "$out" = "exec-probe-ok" ] &&
        pass "rootless PATH search reaches the later executable" ||
        fail "rootless PATH search reaches the later executable" "got '$out'"

    hroot -- /no/such/binary >"$WORK/missing.err" 2>&1
    expect_rc "rootless missing absolute command exits 127" 127 $?
    grep -q "command not found in rootfs: /no/such/binary" "$WORK/missing.err" &&
        pass "rootless missing absolute command message is actionable" ||
        fail "rootless missing absolute command message is actionable" \
             "got '$(cat "$WORK/missing.err")'"

    hroot -- no-such-path-command >"$WORK/missing-path.err" 2>&1
    expect_rc "rootless missing PATH command exits 127" 127 $?
    grep -q "command not found in rootfs (PATH=" "$WORK/missing-path.err" &&
        pass "rootless missing PATH command names PATH" ||
        fail "rootless missing PATH command names PATH" \
             "got '$(cat "$WORK/missing-path.err")'"

    printf '#!/bin/sh\n' >"$ROOTFS/bin/not-executable"
    chmod 0644 "$ROOTFS/bin/not-executable"
    hroot -- /bin/not-executable >"$WORK/noexec.err" 2>&1
    expect_rc "rootless non-executable command exits 126" 126 $?
    grep -q "not executable or not a regular file in rootfs: /bin/not-executable" \
        "$WORK/noexec.err" &&
        pass "rootless non-executable command message is actionable" ||
        fail "rootless non-executable command message is actionable" \
             "got '$(cat "$WORK/noexec.err")'"

    hroot -- noexec-only >"$WORK/noexec-path.err" 2>&1
    expect_rc "rootless PATH with only non-executable candidates exits 126" 126 $?
    grep -q "not executable in rootfs (PATH=" "$WORK/noexec-path.err" &&
        pass "rootless non-executable PATH message names PATH" ||
        fail "rootless non-executable PATH message names PATH" \
             "got '$(cat "$WORK/noexec-path.err")'"

    printf '#!/definitely/missing/interpreter\n' >"$ROOTFS/bin/bad-interp"
    chmod 0755 "$ROOTFS/bin/bad-interp"
    hroot -- /bin/bad-interp >"$WORK/interp.err" 2>&1
    expect_rc "rootless missing shebang interpreter exits 127" 127 $?
    grep -q "dynamic loader or interpreter missing" "$WORK/interp.err" &&
        pass "rootless missing interpreter message is actionable" ||
        fail "rootless missing interpreter message is actionable" \
             "got '$(cat "$WORK/interp.err")'"

    if [ "${HUSK_TEST_FORCE_STATIC_LOADER:-0}" = "1" ]; then
        skip "rootless dynamic-loader failure regression" \
             "forced static-loader fixture (HUSK_TEST_FORCE_STATIC_LOADER=1)"
    elif [ -x /bin/true ] &&
         ldd /bin/true 2>&1 | grep -q "not a dynamic executable"; then
        skip "rootless dynamic-loader failure regression" \
             "/bin/true is statically linked on this host"
    else
        cp /bin/true "$ROOTFS/bin/dyn-true"
        hroot -- /bin/dyn-true >"$WORK/dyn.err" 2>&1
        expect_rc "rootless missing dynamic loader exits 127" 127 $?
        grep -q "exec /bin/dyn-true" "$WORK/dyn.err" &&
            pass "rootless dynamic-loader failure comes from the container handshake" ||
            fail "rootless dynamic-loader failure comes from the container handshake" \
                 "got '$(cat "$WORK/dyn.err")'"
        rm -f "$ROOTFS/bin/dyn-true"
    fi
fi

echo "== Signals, orphan reaping, and termination =="

rec=$(new_record)
timeout 30 "$OWNED_RUN" "$rec" -- "$HUSK" run --rootless --rootfs "$ROOTFS" \
    -- /bin/sh -c 'trap "echo rootless-got-term; exit 42" TERM; while :; do sleep 1; done' \
    >"$WORK/sig.out" 2>"$WORK/sig.err" &
sig_timeout_pid=$!
if info=$(wait_for_record_child "$rec") && record_read "$rec"; then
    sig_owner=$REC_OWNER
    sig_start=$REC_START
    sig_pgid=$REC_PGID
    sig_child=$REC_CHILD
    sleep 1
    if pid_matches "$sig_owner" "$sig_start" &&
       pid_in_group "$sig_child" "$sig_pgid"; then
        kill -TERM "$sig_owner" 2>/dev/null
        kill_rc=$?
    else
        kill_rc=1
        fail "rootless SIGTERM test validated its ownership record"
    fi
    if [ "$kill_rc" -eq 0 ] && owned_wait_status "$rec"; then
        expect_rc "rootless SIGTERM is forwarded and trap exit 42 propagates" \
                  42 "$OWNED_RC"
        grep -q "rootless-got-term" "$WORK/sig.out" &&
            pass "rootless workload observed forwarded SIGTERM" ||
            fail "rootless workload observed forwarded SIGTERM" \
                 "got '$(cat "$WORK/sig.out")'"
        if owned_cleanup_verdict; then
            pass "rootless SIGTERM test left no owned leftovers"
        else
            fail "rootless SIGTERM test left no owned leftovers" \
                 "pids: ${OWNED_LEFTOVER_PIDS:-unknown}"
        fi
        owned_release "$rec"
    else
        fail "rootless SIGTERM supervisor reported completion"
    fi
    if [ "$kill_rc" -ne 0 ]; then
        cleanup_record "$rec" >/dev/null 2>&1 || true
    fi
    wait "$sig_timeout_pid"
    sig_rc=$?
    expect_rc "rootless SIGTERM supervisor exited through timeout" 42 "$sig_rc"
    rm -f "$rec" "$rec.status" "$rec.release"
else
    kill -KILL "$sig_timeout_pid" 2>/dev/null || true
    wait "$sig_timeout_pid" 2>/dev/null || true
    cleanup_record "$rec" >/dev/null 2>&1 || true
    fail "rootless SIGTERM test published its ownership record"
fi

if ! "${CC:-cc}" -static -O2 -Wall -Wextra -Werror \
        -o "$ROOTFS/bin/orphan-probe" "$ROOT/tests/orphan_probe.c" \
        2>"$WORK/orphan-build.err"; then
    fail "build static rootless orphan probe" \
         "$(cat "$WORK/orphan-build.err")"
else
    rec=$(new_record)
    owned_start "$rec" "$HUSK" run --rootless --rootfs "$ROOTFS" -- \
        /bin/orphan-probe >"$WORK/orphan.out" 2>&1
    orphan_pid=$OWNED_PID
    if owned_wait_status "$rec"; then
        expect_rc "rootless orphan probe exits 0" 0 "$OWNED_RC"
        out=$(cat "$WORK/orphan.out")
        [ "$out" = "procs=2" ] &&
            pass "rootless PID 1 reaps an orphaned grandchild" ||
            fail "rootless PID 1 reaps an orphaned grandchild" "got '$out'"
        if owned_cleanup_verdict; then
            pass "rootless orphan probe left no owned leftovers"
        else
            fail "rootless orphan probe left no owned leftovers" \
                 "pids: ${OWNED_LEFTOVER_PIDS:-unknown}"
        fi
        owned_release "$rec"
        owned_finish "$rec" "$orphan_pid" >/dev/null 2>&1
    else
        cleanup_record "$rec" >/dev/null 2>&1 || true
        fail "rootless orphan supervisor reported completion"
    fi
fi

rec=$(new_record)
start=$SECONDS
owned_start "$rec" "$HUSK" run --rootless --rootfs "$ROOTFS" -- \
    /bin/sh -c 'sleep 30 & exit 5' >/dev/null 2>&1
bg_pid=$OWNED_PID
if owned_wait_status "$rec"; then
    expect_rc "rootless workload exit 5 with background child" 5 "$OWNED_RC"
    elapsed=$((SECONDS - start))
    [ "$elapsed" -lt 10 ] &&
        pass "rootless background child did not delay exit (${elapsed}s)" ||
        fail "rootless background child did not delay exit" "${elapsed}s"
    if owned_cleanup_verdict; then
        pass "rootless background-child run left no owned leftovers"
    else
        fail "rootless background-child run left no owned leftovers" \
             "pids: ${OWNED_LEFTOVER_PIDS:-unknown}"
    fi
    owned_release "$rec"
    owned_finish "$rec" "$bg_pid" >/dev/null 2>&1
else
    cleanup_record "$rec" >/dev/null 2>&1 || true
    fail "rootless background-child supervisor reported completion"
fi

rec=$(new_record)
owned_start "$rec" "$HUSK" run --rootless --rootfs "$ROOTFS" -- \
    /bin/sleep 60 >/dev/null 2>&1
crash_owner_pid=$OWNED_PID
if info=$(wait_for_record_child "$rec") && record_read "$rec"; then
    crash_owner=$REC_OWNER
    crash_start=$REC_START
    crash_pgid=$REC_PGID
    crash_child=$REC_CHILD
    sleep 1
    if pid_matches "$crash_owner" "$crash_start" &&
       pid_in_group "$crash_child" "$crash_pgid"; then
        kill -KILL "$crash_child" 2>/dev/null
    else
        fail "rootless parent-death test validated its ownership record"
    fi
    if owned_wait_status "$rec"; then
        expect_rc "SIGKILLed rootless husk parent reports 137" 137 "$OWNED_RC"
        if owned_cleanup_verdict; then
            pass "rootless parent death tears down the workload (PDEATHSIG)"
        else
            fail "rootless parent death tears down the workload (PDEATHSIG)" \
                 "pids: ${OWNED_LEFTOVER_PIDS:-unknown}"
        fi
        owned_release "$rec"
        owned_finish "$rec" "$crash_owner_pid" >/dev/null 2>&1
    else
        cleanup_record "$rec" >/dev/null 2>&1 || true
        fail "rootless parent-death supervisor reported completion"
    fi
else
    cleanup_record "$rec" >/dev/null 2>&1 || true
    fail "rootless parent-death test published its ownership record"
fi

echo "== Repeated rootless launches =="

repeated_ok=1
for _ in $(seq 1 20); do
    rec=$(new_record)
    owned_start "$rec" "$HUSK" run --rootless --rootfs "$ROOTFS" -- \
        /bin/true >/dev/null 2>&1
    pid=$OWNED_PID
    if owned_wait_status "$rec"; then
        owned_cleanup_verdict || repeated_ok=0
        owned_release "$rec"
        owned_finish "$rec" "$pid" >/dev/null 2>&1 || repeated_ok=0
    else
        repeated_ok=0
        cleanup_record "$rec" >/dev/null 2>&1 || true
    fi
done
[ "$repeated_ok" -eq 1 ] &&
    pass "20 repeated rootless launches left no owned leftovers" ||
    fail "20 repeated rootless launches left no owned leftovers"

echo "== Rootless handshake lifecycle and cleanup =="

# Every case below runs through the accepted ownership helper. The helper's
# status snapshot is the pre-cleanup observation; no UID-wide pgrep is used.
# Hooks exist only in the separately built $HUSK_TEST
# (-DHUSK_TEST_HOOKS); the normal $HUSK build has no fault injection.

clear_hooks
clear_workload
rec=$(new_record)
start=$SECONDS
owned_start_watchdog 20 "$WORK/hook-control.out" "$WORK/hook-control.err" \
    "$rec" env HUSK_TEST_DIR="$HOOK_DIR" "$HUSK_TEST" run --rootless \
    --rootfs "$ROOTFS" -- /bin/sh -c ': > /workload-ran'
hook_pid=$OWNED_PID
if owned_wait_status "$rec" 400; then
    elapsed=$((SECONDS - start))
    expect_rc "test-hook control exits 0" 0 "$OWNED_RC"
    if [ "$elapsed" -lt 20 ]; then
        pass "test-hook control completed in ${elapsed}s"
    else
        fail "test-hook control completed in ${elapsed}s"
    fi
    [ -e "$ROOTFS/workload-ran" ] &&
        pass "test-hook control executed the workload" ||
        fail "test-hook control executed the workload"
    check_no_owned_leftovers "test-hook control left no owned leftovers"
    owned_release "$rec"
    owned_finish "$rec" "$hook_pid" >/dev/null 2>&1
else
    cleanup_record "$rec" >/dev/null 2>&1 || true
    fail "test-hook control reported completion"
fi

# Parent dies while the child waits for MAP_READY. The parent hook is after
# MAP_REQUEST; the child has sent its request and is blocked in recv_bounded.
clear_hooks
clear_workload
rec=$(new_record)
start=$SECONDS
owned_start_watchdog 25 "$WORK/parent-death.out" "$WORK/parent-death.err" \
    "$rec" env HUSK_TEST_DIR="$HOOK_DIR" \
    HUSK_TEST_PHASE=parent-map-request "$HUSK_TEST" run --rootless \
    --rootfs "$ROOTFS" -- /bin/sh -c ': > /workload-ran'
hook_pid=$OWNED_PID
if wait_for_hook parent-map-request 200 &&
   wait_for_hook child-map-request-sent 200 &&
   info=$(wait_for_record_child "$rec") && record_read "$rec"; then
    pass "parent-death: parent received MAP_REQUEST and child is waiting"
    capture_hook parent-map-request parent-death-parent.marker
    capture_hook child-map-request-sent parent-death-child.marker
    if pid_matches "$REC_OWNER" "$REC_START" &&
       pid_in_group "$REC_CHILD" "$REC_PGID"; then
        kill -KILL "$REC_CHILD" 2>/dev/null
        pass "parent-death: killed the verified husk parent"
    else
        fail "parent-death: killed the verified husk parent"
    fi
    if owned_wait_status "$rec" 400; then
        elapsed=$((SECONDS - start))
        expect_rc "parent death while child waits exits 137" 137 "$OWNED_RC"
        if [ "$elapsed" -lt 25 ]; then
            pass "parent-death: completed in ${elapsed}s (watchdog 25s)"
        else
            fail "parent-death: completed in ${elapsed}s (watchdog 25s)"
        fi
        if [ ! -s "$WORK/parent-death.err" ]; then
            pass "parent-death: no user-space diagnostic (SIGKILL expected)"
        else
            fail "parent-death: no user-space diagnostic (SIGKILL expected)" \
                 "got '$(cat "$WORK/parent-death.err")'"
        fi
        workload_absent &&
            pass "parent-death: workload did not execute" ||
            fail "parent-death: workload did not execute"
        check_no_owned_leftovers \
            "parent-death: no owned leftovers before release"
        owned_release "$rec"
        owned_finish "$rec" "$hook_pid" >/dev/null 2>&1
    else
        cleanup_record "$rec" >/dev/null 2>&1 || true
        fail "parent-death: supervisor reported completion"
    fi
else
    cleanup_record "$rec" >/dev/null 2>&1 || true
    fail "parent-death: reached the mapping handshake"
fi

# Child dies while the parent is paused after MAP_REQUEST. Releasing the
# parent must make the mapping write fail, report a diagnostic, and reap.
clear_hooks
clear_workload
rec=$(new_record)
start=$SECONDS
owned_start_watchdog 25 "$WORK/child-death.out" "$WORK/child-death.err" \
    "$rec" env HUSK_TEST_DIR="$HOOK_DIR" \
    HUSK_TEST_PHASE=parent-map-request "$HUSK_TEST" run --rootless \
    --rootfs "$ROOTFS" -- /bin/sh -c ': > /workload-ran'
hook_pid=$OWNED_PID
if wait_for_hook parent-map-request 200 &&
   wait_for_hook child-map-request-sent 200; then
    child_pid=$(hook_text parent-map-request)
    capture_hook parent-map-request child-death-parent.marker
    capture_hook child-map-request-sent child-death-child.marker
    case "$child_pid" in
        ''|*[!0-9]*)
            fail "child-death: parent recorded the child PID" \
                 "got '$child_pid'" ;;
        *)
            pass "child-death: parent recorded the child PID ($child_pid)" ;;
    esac
    if [ -n "$child_pid" ] && kill -KILL "$child_pid" 2>/dev/null; then
        pass "child-death: killed the container init during the exchange"
    else
        fail "child-death: killed the container init during the exchange"
    fi
    release_hook parent-map-request
    if owned_wait_status "$rec" 400; then
        elapsed=$((SECONDS - start))
        expect_rc "child death during mapping exits 125" 125 "$OWNED_RC"
        if [ "$elapsed" -lt 25 ]; then
            pass "child-death: completed in ${elapsed}s (watchdog 25s)"
        else
            fail "child-death: completed in ${elapsed}s (watchdog 25s)"
        fi
        grep -q "rootless user-namespace mapping failed" \
            "$WORK/child-death.err" &&
            pass "child-death: parent reported a mapping failure" ||
            fail "child-death: parent reported a mapping failure" \
                 "got '$(cat "$WORK/child-death.err")'"
        grep -q "uid_map" "$WORK/child-death.err" &&
            pass "child-death: diagnostic identifies uid_map" ||
            fail "child-death: diagnostic identifies uid_map" \
                 "got '$(cat "$WORK/child-death.err")'"
        workload_absent &&
            pass "child-death: workload did not execute" ||
            fail "child-death: workload did not execute"
        check_no_owned_leftovers \
            "child-death: no owned leftovers before release"
        owned_release "$rec"
        owned_finish "$rec" "$hook_pid" >/dev/null 2>&1
    else
        cleanup_record "$rec" >/dev/null 2>&1 || true
        fail "child-death: supervisor reported completion"
    fi
else
    cleanup_record "$rec" >/dev/null 2>&1 || true
    fail "child-death: reached the mapping exchange"
fi

# Child stalls before MAP_REQUEST; the parent's own 10 s recv timeout must
# fire, kill/reap the child, and report the parent-side timeout.
clear_hooks
clear_workload
rec=$(new_record)
start=$SECONDS
owned_start_watchdog 25 "$WORK/parent-timeout.out" "$WORK/parent-timeout.err" \
    "$rec" env HUSK_TEST_DIR="$HOOK_DIR" \
    HUSK_TEST_PHASE=child-before-map-request HUSK_TEST_INTERRUPT_WAIT=1 \
    "$HUSK_TEST" run --rootless \
    --rootfs "$ROOTFS" -- /bin/sh -c ': > /workload-ran'
hook_pid=$OWNED_PID
if wait_for_hook child-before-map-request 200; then
    pass "parent-timeout: child reached the pre-request stall"
    capture_hook child-before-map-request parent-timeout-child.marker
else
    fail "parent-timeout: child reached the pre-request stall"
fi
if info=$(wait_for_record_child "$rec") && record_read "$rec"; then
    if start_interrupt_loop "$REC_CHILD"; then
        pass "parent-timeout: SIGUSR1 interrupt loop started"
    else
        fail "parent-timeout: SIGUSR1 interrupt loop started"
    fi
else
    fail "parent-timeout: read the ownership record"
fi
if owned_wait_status "$rec" 500; then
    stop_interrupt_loop
    elapsed=$((SECONDS - start))
    expect_rc "parent mapping timeout exits 125" 125 "$OWNED_RC"
    grep -q "parent: timed out after 10000 ms waiting for user namespace mapping" \
        "$WORK/parent-timeout.err" &&
        pass "parent-timeout: parent reported its 10s timeout" ||
        fail "parent-timeout: parent reported its 10s timeout" \
             "got '$(cat "$WORK/parent-timeout.err")'"
    capture_hook parent-map-timeout parent-timeout-parent.marker
    hook_exists parent-map-timeout &&
        pass "parent-timeout: timeout marker was written" ||
        fail "parent-timeout: timeout marker was written"
    capture_hook parent-map-eintr parent-timeout-eintr.marker
    hook_exists parent-map-eintr &&
        pass "parent-timeout: poll was interrupted and the deadline held" ||
        fail "parent-timeout: poll was interrupted and the deadline held"
    if [ "$elapsed" -ge 9 ] && [ "$elapsed" -le 20 ]; then
        pass "parent-timeout: elapsed ${elapsed}s is consistent with 10s"
    else
        fail "parent-timeout: elapsed ${elapsed}s is consistent with 10s"
    fi
    workload_absent &&
        pass "parent-timeout: workload did not execute" ||
        fail "parent-timeout: workload did not execute"
    check_no_owned_leftovers \
        "parent-timeout: no owned leftovers before release"
    owned_release "$rec"
    owned_finish "$rec" "$hook_pid" >/dev/null 2>&1
else
    stop_interrupt_loop
    cleanup_record "$rec" >/dev/null 2>&1 || true
    fail "parent-timeout: supervisor reported completion"
fi

# Parent stalls after MAP_REQUEST; the child's own 10 s recv timeout must
# fire. The child records its timeout and exit code before exiting; the test
# then releases the parent so it observes the dead child and cleans up.
clear_hooks
clear_workload
rec=$(new_record)
owned_start_watchdog 25 "$WORK/child-timeout.out" "$WORK/child-timeout.err" \
    "$rec" env HUSK_TEST_DIR="$HOOK_DIR" \
    HUSK_TEST_PHASE=parent-map-request HUSK_TEST_INTERRUPT_WAIT=1 \
    "$HUSK_TEST" run --rootless \
    --rootfs "$ROOTFS" -- /bin/sh -c ': > /workload-ran'
hook_pid=$OWNED_PID
if wait_for_hook parent-map-request 200 &&
   wait_for_hook child-map-request-sent 200; then
    child_pid=$(hook_text parent-map-request)
    if [ -n "$child_pid" ] && start_interrupt_loop "$child_pid"; then
        pass "child-timeout: SIGUSR1 interrupt loop started"
    else
        fail "child-timeout: SIGUSR1 interrupt loop started"
    fi
    start=$SECONDS
    if wait_for_hook child-map-timeout 400; then
        elapsed=$((SECONDS - start))
        pass "child-timeout: child's mapping wait timed out"
        capture_hook parent-map-request child-timeout-parent.marker
        capture_hook child-map-request-sent child-timeout-request.marker
        capture_hook child-map-timeout child-timeout-child.marker
        capture_hook child-fail child-timeout-fail.marker
        capture_hook child-map-eintr child-timeout-eintr.marker
        child_timeout_text=$(hook_text child-map-timeout)
        grep -q "timed out after 10000 ms" <<<"$child_timeout_text" &&
            pass "child-timeout: child reported its 10s timeout" ||
            fail "child-timeout: child reported its 10s timeout" \
                 "got '$child_timeout_text'"
        hook_exists child-map-eintr &&
            pass "child-timeout: poll was interrupted and the deadline held" ||
            fail "child-timeout: poll was interrupted and the deadline held"
        child_fail_text=$(hook_text child-fail)
        case "$child_fail_text" in
            *code=125*)
                pass "child-timeout: child recorded exit code 125" ;;
            *)
                fail "child-timeout: child recorded exit code 125" \
                     "got '$child_fail_text'" ;;
        esac
        if [ "$elapsed" -ge 9 ] && [ "$elapsed" -le 20 ]; then
            pass "child-timeout: elapsed ${elapsed}s is consistent with 10s"
        else
            fail "child-timeout: elapsed ${elapsed}s is consistent with 10s"
        fi
        release_hook parent-map-request
        if owned_wait_status "$rec" 400; then
            stop_interrupt_loop
            expect_rc "child-timeout: parent exits 125 after map failure" \
                      125 "$OWNED_RC"
            grep -q "rootless user-namespace mapping failed" \
                "$WORK/child-timeout.err" &&
                pass "child-timeout: parent reported a mapping failure" ||
                fail "child-timeout: parent reported a mapping failure" \
                     "got '$(cat "$WORK/child-timeout.err")'"
            workload_absent &&
                pass "child-timeout: workload did not execute" ||
                fail "child-timeout: workload did not execute"
            check_no_owned_leftovers \
                "child-timeout: no owned leftovers before release"
            owned_release "$rec"
            owned_finish "$rec" "$hook_pid" >/dev/null 2>&1
        else
            stop_interrupt_loop
            cleanup_record "$rec" >/dev/null 2>&1 || true
            fail "child-timeout: supervisor reported completion"
        fi
    else
        stop_interrupt_loop
        release_hook parent-map-request
        cleanup_record "$rec" >/dev/null 2>&1 || true
        fail "child-timeout: child timeout marker was written"
    fi
else
    cleanup_record "$rec" >/dev/null 2>&1 || true
    fail "child-timeout: reached the mapping exchange"
fi

# Child stalls after mapping approval but before forking the workload. The
# parent's 30 s post-mapping setup timeout must fire and reap the child
# without executing the workload.
clear_hooks
clear_workload
rec=$(new_record)
start=$SECONDS
owned_start_watchdog 45 "$WORK/setup-timeout.out" "$WORK/setup-timeout.err" \
    "$rec" env HUSK_TEST_DIR="$HOOK_DIR" \
    HUSK_TEST_PHASE=child-before-workload-fork HUSK_TEST_INTERRUPT_WAIT=1 \
    "$HUSK_TEST" run --rootless \
    --rootfs "$ROOTFS" -- /bin/sh -c ': > /workload-ran'
hook_pid=$OWNED_PID
if wait_for_hook child-before-workload-fork 200; then
    pass "setup-timeout: child reached post-mapping setup"
    capture_hook child-before-workload-fork setup-timeout.marker
else
    fail "setup-timeout: child reached post-mapping setup"
fi
if info=$(wait_for_record_child "$rec") && record_read "$rec"; then
    if start_interrupt_loop "$REC_CHILD"; then
        pass "setup-timeout: SIGUSR1 interrupt loop started"
    else
        fail "setup-timeout: SIGUSR1 interrupt loop started"
    fi
else
    fail "setup-timeout: read the ownership record"
fi
if owned_wait_status "$rec" 900; then
    stop_interrupt_loop
    elapsed=$((SECONDS - start))
    expect_rc "post-mapping setup timeout exits 125" 125 "$OWNED_RC"
    grep -q "timed out after 30000 ms waiting for container setup" \
        "$WORK/setup-timeout.err" &&
        pass "setup-timeout: parent reported its 30s timeout" ||
        fail "setup-timeout: parent reported its 30s timeout" \
             "got '$(cat "$WORK/setup-timeout.err")'"
    capture_hook parent-setup-eintr setup-timeout-eintr.marker
    hook_exists parent-setup-eintr &&
        pass "setup-timeout: setup poll was interrupted and the deadline held" ||
        fail "setup-timeout: setup poll was interrupted and the deadline held"
    if [ "$elapsed" -ge 28 ] && [ "$elapsed" -le 44 ]; then
        pass "setup-timeout: elapsed ${elapsed}s is consistent with 30s"
    else
        fail "setup-timeout: elapsed ${elapsed}s is consistent with 30s"
    fi
    workload_absent &&
        pass "setup-timeout: workload did not execute" ||
        fail "setup-timeout: workload did not execute"
    check_no_owned_leftovers \
        "setup-timeout: no owned leftovers before release"
    owned_release "$rec"
    owned_finish "$rec" "$hook_pid" >/dev/null 2>&1
else
    stop_interrupt_loop
    cleanup_record "$rec" >/dev/null 2>&1 || true
    fail "setup-timeout: supervisor reported completion"
fi

# Denied CLONE_NEWUSER, still with invocation-owned observation.
clear_workload
rec=$(new_record)
start=$SECONDS
owned_start_watchdog 15 "$WORK/deny.out" "$WORK/deny.err" "$rec" \
    "$DENY_WRAPPER" "$HUSK" run --rootless --rootfs "$ROOTFS" -- /bin/true
hook_pid=$OWNED_PID
if owned_wait_status "$rec" 400; then
    elapsed=$((SECONDS - start))
    expect_rc "denied CLONE_NEWUSER exits 125" 125 "$OWNED_RC"
    grep -q "clone new rootless namespaces" "$WORK/deny.err" &&
        pass "denied namespace creation is reported" ||
        fail "denied namespace creation is reported" \
             "got '$(cat "$WORK/deny.err")'"
    grep -Eq "Operation not permitted|Permission denied" "$WORK/deny.err" &&
        pass "denied namespace creation reports the kernel denial" ||
        fail "denied namespace creation reports the kernel denial" \
             "got '$(cat "$WORK/deny.err")'"
    [ "$elapsed" -lt 10 ] &&
        pass "denied namespace creation finishes within the 10s deadline (${elapsed}s)" ||
        fail "denied namespace creation finishes within the 10s deadline" \
             "${elapsed}s"
    check_no_owned_leftovers \
        "denied namespace creation leaves no owned leftovers"
    owned_release "$rec"
    owned_finish "$rec" "$hook_pid" >/dev/null 2>&1
else
    cleanup_record "$rec" >/dev/null 2>&1 || true
    fail "denied namespace creation reported completion"
fi

# Missing /proc mapping files, with invocation-owned observation.
clear_workload
rec=$(new_record)
start=$SECONDS
owned_start_watchdog 15 "$WORK/noproc.out" "$WORK/noproc.err" "$rec" \
    "$NOPROC_WRAPPER" "$HUSK" run --rootless --rootfs "$ROOTFS" -- /bin/true
hook_pid=$OWNED_PID
if owned_wait_status "$rec" 400; then
    elapsed=$((SECONDS - start))
    expect_rc "missing /proc mapping file exits 125" 125 "$OWNED_RC"
    grep -q "rootless user-namespace mapping failed" "$WORK/noproc.err" &&
        pass "mapping failure is reported clearly" ||
        fail "mapping failure is reported clearly" \
             "got '$(cat "$WORK/noproc.err")'"
    grep -q "uid_map" "$WORK/noproc.err" &&
        pass "mapping failure identifies the uid_map operation" ||
        fail "mapping failure identifies the uid_map operation" \
             "got '$(cat "$WORK/noproc.err")'"
    [ "$elapsed" -lt 10 ] &&
        pass "mapping failure finishes within the 10s deadline (${elapsed}s)" ||
        fail "mapping failure finishes within the 10s deadline" "${elapsed}s"
    check_no_owned_leftovers "mapping failure leaves no owned leftovers"
    owned_release "$rec"
    owned_finish "$rec" "$hook_pid" >/dev/null 2>&1
else
    cleanup_record "$rec" >/dev/null 2>&1 || true
    fail "mapping failure reported completion"
fi

# Child setup failure after mapping, with invocation-owned observation.
cp -a "$ROOTFS" "$WORK/badproc-rootfs"
rm -rf "$WORK/badproc-rootfs/proc"
: >"$WORK/badproc-rootfs/proc"
clear_workload
rec=$(new_record)
start=$SECONDS
owned_start_watchdog 15 "$WORK/badproc.out" "$WORK/badproc.err" "$rec" \
    "$HUSK" run --rootless --rootfs "$WORK/badproc-rootfs" -- /bin/true
hook_pid=$OWNED_PID
if owned_wait_status "$rec" 400; then
    elapsed=$((SECONDS - start))
    expect_rc "rootless child setup failure exits 125" 125 "$OWNED_RC"
    grep -q "/proc in rootfs is not a directory" "$WORK/badproc.err" &&
        pass "rootless child setup failure is reported clearly" ||
        fail "rootless child setup failure is reported clearly" \
             "got '$(cat "$WORK/badproc.err")'"
    [ "$elapsed" -lt 10 ] &&
        pass "rootless child setup failure finishes within the 10s deadline (${elapsed}s)" ||
        fail "rootless child setup failure finishes within the 10s deadline" \
             "${elapsed}s"
    check_no_owned_leftovers \
        "rootless child setup failure leaves no owned leftovers"
    owned_release "$rec"
    owned_finish "$rec" "$hook_pid" >/dev/null 2>&1
else
    cleanup_record "$rec" >/dev/null 2>&1 || true
    fail "rootless child setup failure reported completion"
fi

echo "== Handshake diagnostics =="
for _diag in parent-death child-death parent-timeout child-timeout setup-timeout deny noproc badproc; do
    echo "--- ${_diag}.err ---"
    cat "$WORK/${_diag}.err" 2>/dev/null || true
done
for _marker in parent-death-parent.marker parent-death-child.marker \
    child-death-parent.marker child-death-child.marker \
    parent-timeout-child.marker parent-timeout-parent.marker \
    parent-timeout-eintr.marker \
    child-timeout-parent.marker child-timeout-request.marker \
    child-timeout-child.marker child-timeout-fail.marker \
    child-timeout-eintr.marker \
    setup-timeout.marker setup-timeout-eintr.marker; do
    echo "--- ${_marker} ---"
    cat "$WORK/${_marker}" 2>/dev/null || true
    echo
done

echo "== Identity evidence =="
echo "--- caller before launch ---"
cat "$IDENTITY_BEFORE" 2>/dev/null || true
echo "--- inside container ---"
cat "$IDENTITY_INSIDE" 2>/dev/null || true
echo "--- outside host view ---"
cat "$IDENTITY_OUTSIDE" 2>/dev/null || true

echo
echo "passed: $PASS, failed: $FAIL, skipped: $SKIP"
if [ "$SKIP" -ne 0 ]; then
    printf 'skipped checks:\n'
    printf '  - %s\n' "${SKIPPED[@]}"
fi
if [ "$FAIL" -ne 0 ]; then
    printf 'failed checks:\n'
    printf '  - %s\n' "${FAILED[@]}"
    exit 1
fi
exit 0
