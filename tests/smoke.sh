#!/usr/bin/env bash
# Focused smoke/integration tests for the husk MVP.
#
# Must run as root on Linux in a privileged environment: creating mount, PID,
# UTS, IPC, and network namespaces and calling pivot_root is the point.
set -u
set -o pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

HUSK="$ROOT/husk"
ROOTFS="$ROOT/build/rootfs"
WORK="$ROOT/build/test-work"
PASS=0
FAIL=0
SKIP=0
FAILED=()
SKIPPED=()
MARKER_DIR=""
LAUNCHER="$WORK/sigchld-launcher"
LAUNCHER_SLEEP=271
OWNED_RUN="$WORK/owned-run"
LEAK_HELPER="$WORK/leaky-helper"
OWNED_PID=""
CONTROL_PID=""
CONTROL_START=""

if [ "$(id -u)" -ne 0 ]; then
    echo "error: tests must run as root in a privileged Linux environment" >&2
    exit 1
fi
if [ ! -x "$HUSK" ]; then
    echo "error: $HUSK not built (run make)" >&2
    exit 1
fi

# Test-owned artifacts are removed even when a check aborts the script.
cleanup() {
    local record

    for record in "$WORK"/owned-*.record; do
        [ -e "$record" ] && cleanup_record "$record"
    done
    if [ -n "${CONTROL_PID:-}" ] && [ -n "${CONTROL_START:-}" ] &&
       pid_matches "$CONTROL_PID" "$CONTROL_START"; then
        kill -TERM "$CONTROL_PID" 2>/dev/null || true
        wait "$CONTROL_PID" 2>/dev/null || true
    fi
    if [ -n "${MARKER_DIR:-}" ]; then
        rm -rf "$MARKER_DIR"
    fi
    rm -f "$ROOTFS/bin/exec-probe-target" \
          "$ROOTFS/bin/abs-probe" \
          "$ROOTFS/bin/rel-probe" \
          "$ROOTFS/bin/orphan-probe" \
          "$ROOTFS/bin/not-executable" \
          "$ROOTFS/bin/bad-interp" \
          "$ROOTFS/bin/dyn-true" \
          "$ROOTFS/usr/bin/path-probe" \
          "$ROOTFS/usr/local/bin/path-probe" \
          "$ROOTFS/usr/local/bin/noexec-only"
    rm -rf "$WORK/badproc-rootfs"
}

"$ROOT/tests/make-rootfs.sh" "$ROOTFS" >/dev/null || exit 1
mkdir -p "$WORK"
rm -f "$WORK"/*

# Explicit process ownership. Every long-lived invocation runs under
# tests/owned_run.c, which becomes a session/group leader, records
# "<owner> <starttime> <pgid> <child>", and then stays alive until the harness
# releases it. The live owner anchors the numeric PGID: a PGID cannot be
# reused while its leader exists. The harness therefore never signals a
# process group; it signals only a start-time-verified owner PID, and that
# owner performs group cleanup from inside its own live group.
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

# Record allocation uses mktemp in the test-owned work directory. This is
# unique across outstanding invocations without relying on shell subshell
# state, so command substitution cannot make two calls collide.
new_record() {
    mktemp "$WORK/owned-XXXXXX.record"
}

record_read() { # record -> REC_OWNER REC_START REC_PGID REC_CHILD
    local owner start pgid child extra

    REC_OWNER=""; REC_START=""; REC_PGID=""; REC_CHILD=""
    [ -f "$1" ] || return 1
    read -r owner start pgid child extra <"$1" 2>/dev/null || return 1
    [ -z "${extra:-}" ] || return 1
    case "$owner" in ''|*[!0-9]*) return 1 ;; esac
    case "$start" in ''|*[!0-9]*) return 1 ;; esac
    case "$pgid" in ''|*[!0-9]*) return 1 ;; esac
    case "$child" in ''|*[!0-9]*) return 1 ;; esac
    [ "$owner" -gt 1 ] && [ "$start" -gt 0 ] && [ "$child" -gt 1 ] ||
        return 1
    # owned_run is created with setsid(), so its PGID must equal its PID.
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

# Start a supervised command. The supervisor writes RECORD.status once the
# command finishes and then holds the group until RECORD.release exists.
owned_start() { # record, command...
    local record=$1

    shift
    "$OWNED_RUN" "$record" -- "$@" &
    OWNED_PID=$!
}

# Bounded wait for the supervisor's acknowledgement. Populates:
#   OWNED_RC             command exit status observed by the supervisor
#   OWNED_LEFTOVERS      count of owned processes other than the supervisor
#   OWNED_LEFTOVER_PIDS  their PIDs
owned_wait_status() { # record [tenths]
    local record=$1
    local limit=${2:-400}
    local i rc leftover pids

    OWNED_RC=""; OWNED_LEFTOVERS=""; OWNED_LEFTOVER_PIDS=""
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

# The runtime-cleanup verdict used by tests that assess husk: true only when
# the supervisor observed no owned process besides itself before intervention.
owned_cleanup_verdict() {
    [ -n "${OWNED_LEFTOVERS:-}" ] && [ "$OWNED_LEFTOVERS" -eq 0 ]
}

# Cleanup driven only by a verified owner. Returns 0 when cleaned or nothing
# was recorded, and 1 when ownership could not be established. A group is
# never signalled: numeric ID reuse cannot be distinguished from ownership.
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
    # Ownership lifetime is the lifetime of this verified owner process. The
    # start-time check is repeated immediately before each signal.
    if ! pid_matches "$REC_OWNER" "$REC_START"; then
        printf 'cleanup_record: owner %s (start %s) for group %s is not live and matching; refusing to signal that group\n' \
            "$REC_OWNER" "$REC_START" "$REC_PGID" >&2
        mv -f "$record" "$record.unverified" 2>/dev/null || rm -f "$record"
        rm -f "$record.status" "$record.release"
        return 1
    fi

    # Ask the supervisor to finish: release the hold, then interrupt it so a
    # still-running child is forwarded TERM.
    : >"$record.release"
    kill -TERM "$REC_OWNER" 2>/dev/null || true
    for i in $(seq 1 50); do
        pid_matches "$REC_OWNER" "$REC_START" || break
        sleep 0.1
    done
    if pid_matches "$REC_OWNER" "$REC_START"; then
        # The supervisor could not run its own group cleanup. Once it is
        # killed, ownership of the numeric group is unverifiable, so report
        # instead of guessing.
        kill -KILL "$REC_OWNER" 2>/dev/null || true
        printf 'cleanup_record: supervisor %s did not exit after TERM; killed it and left group %s unverified\n' \
            "$REC_OWNER" "$REC_PGID" >&2
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

pass() { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
fail() {
    FAIL=$((FAIL + 1))
    FAILED+=("$1")
    printf 'FAIL %s: %s\n' "$1" "${2:-}"
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

command -v sha256sum >/dev/null 2>&1 || {
    echo "error: sha256sum is required by the test harness" >&2
    exit 1
}

if ! "${CC:-cc}" -O2 -g -std=c17 -Wall -Wextra -Werror -Wformat=2 -Wvla \
        -o "$OWNED_RUN" "$ROOT/tests/owned_run.c" \
        2>"$WORK/owned-run-build.err"; then
    echo "error: cannot build tests/owned_run.c: $(cat "$WORK/owned-run-build.err")" >&2
    exit 1
fi
if ! "${CC:-cc}" -O2 -g -std=c17 -Wall -Wextra -Werror -Wformat=2 -Wvla \
        -o "$LEAK_HELPER" "$ROOT/tests/leaky_helper.c" \
        2>"$WORK/leaky-helper-build.err"; then
    echo "error: cannot build tests/leaky_helper.c: $(cat "$WORK/leaky-helper-build.err")" >&2
    exit 1
fi

trap cleanup EXIT

echo "== CLI and validation =="

"$HUSK" --help >"$WORK/help.txt" 2>&1
expect_rc "help exits 0" 0 $?
grep -q "Usage: husk run --rootfs" "$WORK/help.txt"
[ $? -eq 0 ] && pass "help documents run syntax" || fail "help documents run syntax"

"$HUSK" --version >/dev/null 2>&1
expect_rc "version exits 0" 0 $?

"$HUSK" >/dev/null 2>&1
expect_rc "missing command exits 2" 2 $?

"$HUSK" run --rootfs "$ROOTFS" >/dev/null 2>&1
expect_rc "missing workload command exits 2" 2 $?

"$HUSK" run --rootfs "$ROOTFS" --bogus -- /bin/true >/dev/null 2>&1
expect_rc "unknown option exits 2" 2 $?

"$HUSK" run --rootfs "$WORK/does-not-exist" -- /bin/true >"$WORK/badroot1.err" 2>&1
expect_rc "nonexistent rootfs exits 2" 2 $?
grep -q "invalid rootfs" "$WORK/badroot1.err"
[ $? -eq 0 ] && pass "nonexistent rootfs message is actionable" || fail "nonexistent rootfs message is actionable"

"$HUSK" run --rootfs /bin/true -- /bin/true >"$WORK/badroot2.err" 2>&1
expect_rc "non-directory rootfs exits 2" 2 $?

"$HUSK" run --rootfs / -- /bin/true >"$WORK/badroot3.err" 2>&1
expect_rc "rootfs / is refused with exit 2" 2 $?

echo "== Basic execution and status propagation =="

"$HUSK" run --rootfs "$ROOTFS" -- /bin/true
expect_rc "run /bin/true" 0 $?

"$HUSK" run --rootfs="$ROOTFS" -- /bin/true
expect_rc "--rootfs=DIR form works" 0 $?

out=$("$HUSK" run --rootfs "$ROOTFS" -- /bin/sh -c 'echo husk-mvp-ok' 2>&1)
rc=$?
expect_rc "noninteractive command exits 0" 0 "$rc"
if [ "$out" = "husk-mvp-ok" ]; then pass "noninteractive output is correct"; else fail "noninteractive output is correct" "got '$out'"; fi

out=$(printf 'echo stdin-ok\nexit 0\n' | "$HUSK" run --rootfs "$ROOTFS" -- /bin/sh 2>&1)
rc=$?
expect_rc "shell reading commands from stdin exits 0" 0 "$rc"
if printf '%s\n' "$out" | grep -qx 'stdin-ok'; then pass "container stdin is connected"; else fail "container stdin is connected" "got '$out'"; fi

"$HUSK" run --rootfs "$ROOTFS" -- /bin/sh -c 'exit 7' >/dev/null 2>&1
expect_rc "workload exit 7 propagates" 7 $?

"$HUSK" run --rootfs "$ROOTFS" -- /bin/false >/dev/null 2>&1
expect_rc "workload exit 1 propagates" 1 $?

"$HUSK" run --rootfs "$ROOTFS" -- /bin/sh -c 'kill -TERM $$' >/dev/null 2>&1
out=$?
expect_rc "workload killed by SIGTERM maps to 128+15" 143 "$out"

echo "== Command resolution inside the container =="

# Build static helpers and fixtures. exec_probe is deliberately installed at
# /bin/exec-probe-target and reached through an absolute symlink, so host-side
# stat() of the symlink would follow it against the host root and fail.
if ! "${CC:-cc}" -static -O2 -Wall -Wextra -Werror \
        -o "$ROOTFS/bin/exec-probe-target" "$ROOT/tests/exec_probe.c" \
        2>"$WORK/exec-probe-build.err"; then
    fail "build static exec probe" "$(cat "$WORK/exec-probe-build.err")"
    exit 1
fi
if ! "${CC:-cc}" -static -O2 -Wall -Wextra -Werror \
        -o "$ROOTFS/bin/orphan-probe" "$ROOT/tests/orphan_probe.c" \
        2>"$WORK/orphan-build.err"; then
    fail "build static orphan probe" "$(cat "$WORK/orphan-build.err")"
    exit 1
fi
ln -sf /bin/exec-probe-target "$ROOTFS/bin/abs-probe"
printf '#!/bin/sh\necho relative-ok\n' >"$ROOTFS/bin/rel-probe"
chmod 0755 "$ROOTFS/bin/rel-probe"
mkdir -p "$ROOTFS/usr/local/bin" "$ROOTFS/usr/bin"
cp "$ROOTFS/bin/exec-probe-target" "$ROOTFS/usr/bin/path-probe"
chmod 0755 "$ROOTFS/usr/bin/path-probe"
# /usr/local/bin precedes /usr/bin in HUSK_PATH_DEFAULT. This decoy exists but
# is not executable; execvp() must continue to the later working candidate.
printf '#!/bin/sh\necho path-decoy-should-not-run\n' \
    >"$ROOTFS/usr/local/bin/path-probe"
chmod 0644 "$ROOTFS/usr/local/bin/path-probe"
printf '#!/bin/sh\necho noexec-only-should-not-run\n' \
    >"$ROOTFS/usr/local/bin/noexec-only"
chmod 0644 "$ROOTFS/usr/local/bin/noexec-only"

if [ -e /bin/exec-probe-target ]; then
    fail "absolute symlink target is absent on the host (test precondition)"
else
    pass "absolute symlink target exists only inside the rootfs"
fi

out=$("$HUSK" run --rootfs "$ROOTFS" -- /bin/exec-probe-target 2>&1)
rc=$?
expect_rc "absolute path to static probe exits 0" 0 "$rc"
[ "$out" = "exec-probe-ok" ] && pass "absolute path executes the probe" || fail "absolute path executes the probe" "got '$out'"

out=$("$HUSK" run --rootfs "$ROOTFS" -- /bin/abs-probe 2>&1)
rc=$?
expect_rc "absolute symlink resolves inside the rootfs" 0 "$rc"
[ "$out" = "exec-probe-ok" ] && pass "absolute symlink executes the rootfs target" || fail "absolute symlink executes the rootfs target" "got '$out'"

out=$("$HUSK" run --rootfs "$ROOTFS" -- usr/bin/path-probe 2>&1)
rc=$?
expect_rc "relative path invocation exits 0" 0 "$rc"
[ "$out" = "exec-probe-ok" ] && pass "relative path resolves from container /" || fail "relative path resolves from container /" "got '$out'"

out=$("$HUSK" run --rootfs "$ROOTFS" -- path-probe 2>&1)
rc=$?
expect_rc "PATH search skips an early non-executable candidate" 0 "$rc"
[ "$out" = "exec-probe-ok" ] && pass "PATH search reaches the later executable" || fail "PATH search reaches the later executable" "got '$out'"

"$HUSK" run --rootfs "$ROOTFS" -- /no/such/binary >"$WORK/missing.err" 2>&1
expect_rc "missing absolute command exits 127" 127 $?
grep -q "command not found in rootfs: /no/such/binary" "$WORK/missing.err"
[ $? -eq 0 ] && pass "missing absolute command message is actionable" || fail "missing absolute command message is actionable" "got '$(cat "$WORK/missing.err")'"

"$HUSK" run --rootfs "$ROOTFS" -- no-such-path-command >"$WORK/missing-path.err" 2>&1
expect_rc "missing PATH command exits 127" 127 $?
grep -q "command not found in rootfs (PATH=" "$WORK/missing-path.err"
[ $? -eq 0 ] && pass "missing PATH command message names PATH" || fail "missing PATH command message names PATH" "got '$(cat "$WORK/missing-path.err")'"

printf '#!/bin/sh\n' >"$ROOTFS/bin/not-executable"
chmod 0644 "$ROOTFS/bin/not-executable"
"$HUSK" run --rootfs "$ROOTFS" -- /bin/not-executable >"$WORK/noexec.err" 2>&1
expect_rc "non-executable command exits 126" 126 $?
grep -q "not executable or not a regular file in rootfs: /bin/not-executable" "$WORK/noexec.err"
[ $? -eq 0 ] && pass "non-executable command message is actionable" || fail "non-executable command message is actionable" "got '$(cat "$WORK/noexec.err")'"

"$HUSK" run --rootfs "$ROOTFS" -- noexec-only >"$WORK/noexec-path.err" 2>&1
expect_rc "PATH with only non-executable candidates exits 126" 126 $?
grep -q "not executable in rootfs (PATH=" "$WORK/noexec-path.err"
[ $? -eq 0 ] && pass "non-executable PATH message names PATH" || fail "non-executable PATH message names PATH" "got '$(cat "$WORK/noexec-path.err")'"

printf '#!/definitely/missing/interpreter\n' >"$ROOTFS/bin/bad-interp"
chmod 0755 "$ROOTFS/bin/bad-interp"
"$HUSK" run --rootfs "$ROOTFS" -- /bin/bad-interp >"$WORK/interp.err" 2>&1
expect_rc "missing shebang interpreter exits 127" 127 $?
grep -q "dynamic loader or interpreter missing" "$WORK/interp.err"
[ $? -eq 0 ] && pass "missing interpreter message is actionable" || fail "missing interpreter message is actionable" "got '$(cat "$WORK/interp.err")'"

if [ "${HUSK_TEST_FORCE_STATIC_LOADER:-0}" = "1" ]; then
    skip "dynamic-loader failure regression" \
         "forced static-loader fixture (HUSK_TEST_FORCE_STATIC_LOADER=1)"
elif [ -x /bin/true ] && ldd /bin/true 2>&1 | grep -q "not a dynamic executable"; then
    skip "dynamic-loader failure regression" \
         "/bin/true is statically linked on this host"
else
    cp /bin/true "$ROOTFS/bin/dyn-true"
    "$HUSK" run --rootfs "$ROOTFS" -- /bin/dyn-true >"$WORK/dyn.err" 2>&1
    expect_rc "missing dynamic loader is reported (exit 127)" 127 $?
    grep -q "exec /bin/dyn-true" "$WORK/dyn.err"
    [ $? -eq 0 ] && pass "dynamic-loader failure comes from the container handshake" || fail "dynamic-loader failure comes from the container handshake" "got '$(cat "$WORK/dyn.err")'"
    rm -f "$ROOTFS/bin/dyn-true"
fi

echo "== UTS, PID, and mount namespaces =="

host_name_before=$(hostname)
mounts_before=$(sha256sum </proc/self/mountinfo)

out=$("$HUSK" run --rootfs "$ROOTFS" --hostname husk-test -- /bin/sh -c 'hostname; uname -n; echo pid=$$; cat /proc/1/comm' 2>&1)
rc=$?
expect_rc "hostname/pid probe exits 0" 0 "$rc"
if printf '%s\n' "$out" | head -n1 | grep -qx 'husk-test' &&
   printf '%s\n' "$out" | sed -n '2p' | grep -qx 'husk-test'; then
    pass "container hostname is isolated (hostname and uname -n)"
else
    fail "container hostname is isolated (hostname and uname -n)" "got '$out'"
fi
if printf '%s\n' "$out" | grep -qx 'pid=2'; then
    pass "workload runs as PID 2 with husk as PID 1"
else
    fail "workload runs as PID 2 with husk as PID 1" "got '$out'"
fi
if printf '%s\n' "$out" | tail -n1 | grep -qx 'husk'; then
    pass "container init (PID 1) is husk"
else
    fail "container init (PID 1) is husk" "got '$out'"
fi

echo "== Host filesystem marker isolation =="

MARKER_DIR=$(mktemp -d "$WORK/host-marker.XXXXXX") || exit 1
MARKER="$MARKER_DIR/marker-$$"
printf 'host-only-marker-%s\n' "$$" >"$MARKER"
marker_content=$(cat "$MARKER")

case "$MARKER" in
    "$ROOTFS"/*)
        fail "marker is outside the supplied rootfs" "$MARKER"
        ;;
    *)
        pass "marker is outside the supplied rootfs ($MARKER)"
        ;;
esac
if [ -f "$MARKER" ] && [ -r "$MARKER" ]; then
    pass "marker exists and is readable at its exact host path"
else
    fail "marker exists and is readable at its exact host path" "$MARKER"
fi

# Probe the identical absolute path inside husk. If the host filesystem leaked
# through, the assertion would be false there just as it is on the host.
out=$("$HUSK" run --rootfs "$ROOTFS" -- /bin/sh -c 'test ! -e "$1" && echo absent' sh "$MARKER" 2>&1)
rc=$?
expect_rc "probe for host marker path exits 0" 0 "$rc"
if [ "$out" = "absent" ]; then
    pass "host marker path is absent inside the container"
else
    fail "host marker path is absent inside the container" "got '$out'"
fi

"$HUSK" run --rootfs "$ROOTFS" -- /bin/cat "$MARKER" >/dev/null 2>&1
if [ $? -ne 0 ]; then
    pass "reading the exact host marker path inside the container fails"
else
    fail "reading the exact host marker path inside the container fails"
fi

# Negative control: the same absence assertion must be false on the host,
# proving the inside-container result above is not vacuous.
if test ! -e "$MARKER"; then
    fail "negative control: absence assertion is false on the host" "$MARKER"
else
    pass "negative control: same absence assertion is false on the host"
fi

if [ "$(cat "$MARKER")" = "$marker_content" ]; then
    pass "marker content is unchanged after container probes"
else
    fail "marker content is unchanged after container probes"
fi

echo "== Network namespace =="

dev=$("$HUSK" run --rootfs "$ROOTFS" -- /bin/cat /proc/net/dev 2>&1)
dev_rc=$?
links=$("$HUSK" run --rootfs "$ROOTFS" -- /bin/ip -o link 2>&1)
links_rc=$?
addrs=$("$HUSK" run --rootfs "$ROOTFS" -- /bin/ip -o addr 2>&1)
addrs_rc=$?
routes=$("$HUSK" run --rootfs "$ROOTFS" -- /bin/ip route 2>&1)
routes_rc=$?

expect_rc "/proc/net/dev collection exits 0" 0 "$dev_rc"
expect_rc "ip -o link collection exits 0" 0 "$links_rc"
expect_rc "ip -o addr collection exits 0" 0 "$addrs_rc"
expect_rc "ip route collection exits 0" 0 "$routes_rc"

if [ "$dev_rc" -eq 0 ] && [ "$links_rc" -eq 0 ] &&
   [ "$addrs_rc" -eq 0 ] && [ "$routes_rc" -eq 0 ]; then
    if printf '%s\n' "$links" | grep -q ': lo:'; then
        pass "network namespace contains loopback"
    else
        fail "network namespace contains loopback" "links='$links'"
    fi
    if printf '%s\n' "$links" | grep -q ': lo:.*<LOOPBACK'; then
        pass "loopback is present with LOOPBACK flag"
    else
        fail "loopback is present with LOOPBACK flag" "links='$links'"
    fi
    if printf '%s\n' "$links" | grep -q ': lo:.*UP'; then
        fail "loopback is down (no configured connectivity)" "links='$links'"
    else
        pass "loopback is down (no configured connectivity)"
    fi

    # Kernel-created tunnel devices (tunl0, gre0, sit0, ...) are expected and
    # inactive. No non-loopback interface may be up.
    nonlo_up=$(printf '%s\n' "$links" | awk -F': ' '
        { name=$2; sub(/@.*/, "", name);
          if (name != "lo" && $0 ~ /<[^>]*UP[^>]*>/) print name }')
    if [ -z "$nonlo_up" ]; then
        pass "no non-loopback interface is up"
    else
        fail "no non-loopback interface is up" "up: $nonlo_up"
    fi

    external_names=$(printf '%s\n' "$links" | awk -F': ' '
        { name=$2; sub(/@.*/, "", name);
          if (name ~ /^(eth|wlan|enp|eno|ens|enx|wwan|wwp|bond|docker|veth)/)
              print name }')
    if [ -z "$external_names" ]; then
        pass "no external interface names are present"
    else
        fail "no external interface names are present" "found: $external_names"
    fi

    if [ -z "$addrs" ]; then
        pass "no addresses are configured in the network namespace"
    else
        fail "no addresses are configured in the network namespace" "addrs='$addrs'"
    fi
    if [ -z "$routes" ]; then
        pass "no routes are configured in the network namespace"
    else
        fail "no routes are configured in the network namespace" "routes='$routes'"
    fi
else
    fail "network assertions skipped because a probe command failed" \
         "dev_rc=$dev_rc links_rc=$links_rc addrs_rc=$addrs_rc routes_rc=$routes_rc"
fi

host_netns=$(readlink /proc/self/ns/net 2>/dev/null || true)
container_netns=$("$HUSK" run --rootfs "$ROOTFS" -- /bin/readlink /proc/self/ns/net 2>&1)
netns_rc=$?
expect_rc "container readlink /proc/self/ns/net exits 0" 0 "$netns_rc"
if [ -n "$host_netns" ] && [ -n "$container_netns" ] &&
   [ "$container_netns" != "$host_netns" ]; then
    pass "container network namespace identity differs from the host ($container_netns)"
else
    fail "container network namespace identity differs from the host" \
         "host='$host_netns' container='$container_netns'"
fi

if [ -x "$ROOTFS/bin/ping" ]; then
    "$HUSK" run --rootfs "$ROOTFS" -- /bin/ping -c 1 -W 1 192.0.2.1 >/dev/null 2>&1
    ping_rc=$?
    if [ "$ping_rc" -eq 1 ]; then
        pass "connectivity probe to 192.0.2.1 fails with rc 1 (single probe, not comprehensive proof)"
    else
        fail "connectivity probe to 192.0.2.1 fails with rc 1" "got rc $ping_rc"
    fi
else
    fail "ping applet available for connectivity probe"
fi

host_name_after=$(hostname)
mounts_after=$(sha256sum </proc/self/mountinfo)
if [ "$host_name_before" = "$host_name_after" ]; then pass "host hostname unchanged"; else fail "host hostname unchanged" "$host_name_before -> $host_name_after"; fi
if [ "$mounts_before" = "$mounts_after" ]; then pass "host mount state unchanged"; else fail "host mount state unchanged"; fi
if mountpoint -q "$ROOTFS/proc" 2>/dev/null; then fail "rootfs/proc is not mounted on the host"; else pass "rootfs/proc is not mounted on the host"; fi

echo "== Setup and exec failure reporting =="

cp -a "$ROOTFS" "$WORK/badproc-rootfs"
rm -rf "$WORK/badproc-rootfs/proc"
: >"$WORK/badproc-rootfs/proc"
"$HUSK" run --rootfs "$WORK/badproc-rootfs" -- /bin/true >"$WORK/badproc.err" 2>&1
expect_rc "rootfs with /proc as a file fails setup" 125 $?
grep -q "/proc in rootfs is not a directory" "$WORK/badproc.err"
[ $? -eq 0 ] && pass "setup failure message is actionable" || fail "setup failure message is actionable" "got '$(cat "$WORK/badproc.err")'"
rm -rf "$WORK/badproc-rootfs"

echo "== SIGCHLD normalization =="

if "${CC:-cc}" -O2 -Wall -Wextra -Werror \
        -o "$LAUNCHER" "$ROOT/tests/sigchld_launcher.c" \
        2>"$WORK/launcher-build.err"; then
    pass "built SIGCHLD=SIG_IGN launcher helper"

    rec=$(new_record)
    owned_start "$rec" "$LAUNCHER" "$HUSK" run --rootfs "$ROOTFS" -- \
        /bin/sh -c 'echo launcher-ok' >"$WORK/launcher-ok.out" 2>&1
    owned_pid=$OWNED_PID
    if owned_wait_status "$rec"; then
        rc=$OWNED_RC
        out=$(cat "$WORK/launcher-ok.out")
        expect_rc "SIGCHLD=SIG_IGN launcher: workload exits 0" 0 "$rc"
        if [ "$out" = "launcher-ok" ]; then
            pass "SIGCHLD=SIG_IGN launcher: workload output is correct"
        else
            fail "SIGCHLD=SIG_IGN launcher: workload output is correct" "got '$out'"
        fi
        # Observed before release: husk, not the harness, must have removed
        # its workload. The supervisor anchors the group and is excluded.
        if owned_cleanup_verdict; then
            pass "SIGCHLD=SIG_IGN launcher: no owned leftovers before harness cleanup"
        else
            fail "SIGCHLD=SIG_IGN launcher: no owned leftovers before harness cleanup" \
                 "pids: ${OWNED_LEFTOVER_PIDS:-unknown}"
        fi
        owned_release "$rec"
        owned_finish "$rec" "$owned_pid" >/dev/null 2>&1
    else
        cleanup_record "$rec" >/dev/null 2>&1 || true
        fail "SIGCHLD=SIG_IGN launcher: supervisor reported completion"
    fi

    rec=$(new_record)
    owned_start "$rec" "$LAUNCHER" "$HUSK" run --rootfs "$ROOTFS" -- \
        /bin/sh -c 'exit 7' >/dev/null 2>&1
    owned_pid=$OWNED_PID
    if owned_wait_status "$rec"; then
        rc=$OWNED_RC
        expect_rc "SIGCHLD=SIG_IGN launcher: exit 7 propagates" 7 "$rc"
        if owned_cleanup_verdict; then
            pass "SIGCHLD=SIG_IGN launcher: exit-7 run left no owned leftovers"
        else
            fail "SIGCHLD=SIG_IGN launcher: exit-7 run left no owned leftovers" \
                 "pids: ${OWNED_LEFTOVER_PIDS:-unknown}"
        fi
        owned_release "$rec"
        owned_finish "$rec" "$owned_pid" >/dev/null 2>&1
    else
        cleanup_record "$rec" >/dev/null 2>&1 || true
        fail "SIGCHLD=SIG_IGN launcher: exit-7 supervisor reported completion"
    fi

    rec=$(new_record)
    owned_start "$rec" "$LAUNCHER" "$HUSK" run --rootfs "$ROOTFS" -- \
        /bin/orphan-probe >"$WORK/launcher-orphan.out" 2>&1
    owned_pid=$OWNED_PID
    if owned_wait_status "$rec"; then
        rc=$OWNED_RC
        out=$(cat "$WORK/launcher-orphan.out")
        expect_rc "SIGCHLD=SIG_IGN launcher: orphan probe exits 0" 0 "$rc"
        if [ "$out" = "procs=2" ]; then
            pass "SIGCHLD=SIG_IGN launcher: PID 1 reaps an orphaned grandchild"
        else
            fail "SIGCHLD=SIG_IGN launcher: PID 1 reaps an orphaned grandchild" "got '$out'"
        fi
        if owned_cleanup_verdict; then
            pass "SIGCHLD=SIG_IGN launcher: orphan probe left no owned leftovers"
        else
            fail "SIGCHLD=SIG_IGN launcher: orphan probe left no owned leftovers" \
                 "pids: ${OWNED_LEFTOVER_PIDS:-unknown}"
        fi
        owned_release "$rec"
        owned_finish "$rec" "$owned_pid" >/dev/null 2>&1
    else
        cleanup_record "$rec" >/dev/null 2>&1 || true
        fail "SIGCHLD=SIG_IGN launcher: orphan-probe supervisor reported completion"
    fi

    rec=$(new_record)
    start=$SECONDS
    owned_start "$rec" "$LAUNCHER" "$HUSK" run --rootfs "$ROOTFS" -- \
        /bin/sh -c "sleep $LAUNCHER_SLEEP & exit 0" >/dev/null 2>&1
    owned_pid=$OWNED_PID
    if owned_wait_status "$rec"; then
        rc=$OWNED_RC
        elapsed=$((SECONDS - start))
        expect_rc "SIGCHLD=SIG_IGN launcher: workload with background child exits 0" 0 "$rc"
        if [ "$elapsed" -lt 15 ]; then
            pass "SIGCHLD=SIG_IGN launcher: completed within the 15s deadline (${elapsed}s)"
        else
            fail "SIGCHLD=SIG_IGN launcher: completed within the 15s deadline" "${elapsed}s"
        fi
        if owned_cleanup_verdict; then
            pass "SIGCHLD=SIG_IGN launcher: no workload child left behind before harness cleanup"
        else
            fail "SIGCHLD=SIG_IGN launcher: no workload child left behind before harness cleanup" \
                 "pids: ${OWNED_LEFTOVER_PIDS:-unknown}"
        fi
        owned_release "$rec"
        owned_finish "$rec" "$owned_pid" >/dev/null 2>&1
    else
        cleanup_record "$rec" >/dev/null 2>&1 || true
        fail "SIGCHLD=SIG_IGN launcher: background-child supervisor reported completion"
    fi
else
    fail "build SIGCHLD launcher" "$(cat "$WORK/launcher-build.err")"
fi

echo "== Signals, PID 1 reaping, and termination =="

rec=$(new_record)
timeout 20 "$OWNED_RUN" "$rec" -- "$HUSK" run --rootfs "$ROOTFS" -- /bin/sh -c \
    'trap "echo got-term; exit 42" TERM; while :; do sleep 1; done' \
    >"$WORK/sig.out" 2>"$WORK/sig.err" &
sig_timeout_pid=$!
if info=$(wait_for_record_child "$rec") && record_read "$rec"; then
    sig_owner=$REC_OWNER
    sig_start=$REC_START
    sig_pgid=$REC_PGID
    sig_child=$REC_CHILD
    sleep 1
    # Signal only the verified owner. A mismatch is reported, never guessed.
    if pid_matches "$sig_owner" "$sig_start" && pid_in_group "$sig_child" "$sig_pgid"; then
        kill -TERM "$sig_owner" 2>/dev/null
        kill_rc=$?
    else
        kill_rc=1
        fail "SIGTERM test validated its ownership record"
    fi
    if [ "$kill_rc" -eq 0 ] && owned_wait_status "$rec"; then
        expect_rc "SIGTERM is forwarded and trap exit 42 propagates" 42 "$OWNED_RC"
        grep -q "got-term" "$WORK/sig.out"
        [ $? -eq 0 ] && pass "workload observed forwarded SIGTERM" || fail "workload observed forwarded SIGTERM" "got '$(cat "$WORK/sig.out")'"
        if owned_cleanup_verdict; then
            pass "SIGTERM test left no owned leftovers before harness cleanup"
        else
            fail "SIGTERM test left no owned leftovers before harness cleanup" \
                 "pids: ${OWNED_LEFTOVER_PIDS:-unknown}"
        fi
        owned_release "$rec"
    else
        fail "SIGTERM test: supervisor reported completion"
    fi
    if [ "$kill_rc" -ne 0 ]; then
        cleanup_record "$rec" >/dev/null 2>&1 || true
    fi
    wait "$sig_timeout_pid"
    sig_rc=$?
    expect_rc "SIGTERM test supervisor exited through timeout" 42 "$sig_rc"
    rm -f "$rec" "$rec.status" "$rec.release"
else
    kill -KILL "$sig_timeout_pid" 2>/dev/null || true
    wait "$sig_timeout_pid" 2>/dev/null || true
    cleanup_record "$rec" >/dev/null 2>&1 || true
    fail "SIGTERM test published its ownership record"
fi

rec=$(new_record)
owned_start "$rec" "$HUSK" run --rootfs "$ROOTFS" -- \
    /bin/orphan-probe >"$WORK/orphan.out" 2>&1
owned_pid=$OWNED_PID
if owned_wait_status "$rec"; then
    rc=$OWNED_RC
    out=$(cat "$WORK/orphan.out")
    expect_rc "orphan probe exits 0" 0 "$rc"
    if [ "$out" = "procs=2" ]; then
        pass "PID 1 reaps an orphaned grandchild (no zombie)"
    else
        fail "PID 1 reaps an orphaned grandchild (no zombie)" "got '$out'"
    fi
    if owned_cleanup_verdict; then
        pass "orphan-reaping run left no owned leftovers before harness cleanup"
    else
        fail "orphan-reaping run left no owned leftovers before harness cleanup" \
             "pids: ${OWNED_LEFTOVER_PIDS:-unknown}"
    fi
    owned_release "$rec"
    owned_finish "$rec" "$owned_pid" >/dev/null 2>&1
else
    cleanup_record "$rec" >/dev/null 2>&1 || true
    fail "orphan-probe supervisor reported completion"
fi

rec=$(new_record)
start=$SECONDS
owned_start "$rec" "$HUSK" run --rootfs "$ROOTFS" -- \
    /bin/sh -c 'sleep 30 & exit 5' >/dev/null 2>&1
owned_pid=$OWNED_PID
if owned_wait_status "$rec"; then
    rc=$OWNED_RC
    elapsed=$((SECONDS - start))
    expect_rc "workload exit 5 with background child" 5 "$rc"
    if [ "$elapsed" -lt 10 ]; then pass "background child did not delay exit (${elapsed}s)"; else fail "background child did not delay exit" "${elapsed}s"; fi
    if owned_cleanup_verdict; then
        pass "background-child run left no owned leftovers before harness cleanup"
    else
        fail "background-child run left no owned leftovers before harness cleanup" \
             "pids: ${OWNED_LEFTOVER_PIDS:-unknown}"
    fi
    owned_release "$rec"
    owned_finish "$rec" "$owned_pid" >/dev/null 2>&1
else
    cleanup_record "$rec" >/dev/null 2>&1 || true
    fail "background-child supervisor reported completion"
fi

echo "== Abrupt parent death =="

rec=$(new_record)
owned_start "$rec" "$HUSK" run --rootfs "$ROOTFS" -- /bin/sleep 60 >/dev/null 2>&1
crash_owner_pid=$OWNED_PID
if info=$(wait_for_record_child "$rec") && record_read "$rec"; then
    crash_owner=$REC_OWNER
    crash_start=$REC_START
    crash_pgid=$REC_PGID
    crash_child=$REC_CHILD
    sleep 1
    # Kill husk itself (verified group member), not the supervisor that
    # anchors ownership.
    if pid_matches "$crash_owner" "$crash_start" &&
       pid_in_group "$crash_child" "$crash_pgid"; then
        kill -KILL "$crash_child" 2>/dev/null
    else
        fail "parent-death test validated its ownership record"
    fi
    if owned_wait_status "$rec"; then
        expect_rc "SIGKILLed husk parent reports 137" 137 "$OWNED_RC"
        if owned_cleanup_verdict; then
            pass "parent death tears down the workload (PDEATHSIG)"
        else
            fail "parent death tears down the workload (PDEATHSIG)" \
                 "pids: ${OWNED_LEFTOVER_PIDS:-unknown}"
        fi
        owned_release "$rec"
        owned_finish "$rec" "$crash_owner_pid" >/dev/null 2>&1
    else
        cleanup_record "$rec" >/dev/null 2>&1 || true
        fail "parent-death supervisor reported completion"
    fi
else
    cleanup_record "$rec" >/dev/null 2>&1 || true
    fail "parent-death test published its ownership record"
fi


echo "== Cleanup ownership regression =="

# A control process deliberately uses the same command line as the workload
# that the old broad pkill rule matched. It lives in the invoking shell's
# process group, outside every owned_run group.
sleep "$LAUNCHER_SLEEP" &
CONTROL_PID=$!
CONTROL_START=$(proc_starttime "$CONTROL_PID" 2>/dev/null || true)
if pid_matches "$CONTROL_PID" "$CONTROL_START"; then
    pass "cleanup regression: control sleep started outside owned groups"
else
    fail "cleanup regression: control sleep started outside owned groups"
fi

# Normal completion path. This intentionally exercises the supervisor's own
# cleanup: a direct command leaves a background child, which must still be
# present at the observation point and gone after release.
rec=$(new_record)
owned_start "$rec" /bin/sh -c "sleep $LAUNCHER_SLEEP & exit 0" >/dev/null 2>&1
owned_pid=$OWNED_PID
pgid=""
if info=$(wait_for_record_child "$rec"); then
    read -r _ _ pgid _ <<<"$info"
fi
if owned_wait_status "$rec"; then
    expect_rc "cleanup regression: normal owned workload exits 0" 0 "$OWNED_RC"
    if [ "${OWNED_LEFTOVERS:-0}" -ge 1 ]; then
        pass "cleanup regression: descendant observed before supervisor release"
    else
        fail "cleanup regression: descendant observed before supervisor release"
    fi
    if pid_matches "$CONTROL_PID" "$CONTROL_START"; then
        pass "cleanup regression: control survives normal observation"
    else
        fail "cleanup regression: control survives normal observation"
    fi
    owned_release "$rec"
    owned_finish "$rec" "$owned_pid" >/dev/null 2>&1
    if wait_group_gone "$pgid"; then
        pass "cleanup regression: normal owned workload and descendants are gone"
    else
        fail "cleanup regression: normal owned workload and descendants are gone" "pgid=$pgid"
    fi
else
    cleanup_record "$rec" >/dev/null 2>&1 || true
    fail "cleanup regression: normal supervisor reported completion"
fi

# Forced timeout path: timeout interrupts the supervisor, which forwards TERM.
# The supervisor still holds the group until the harness releases it.
rec=$(new_record)
timeout 2 "$OWNED_RUN" "$rec" -- /bin/sh -c \
    "sleep $LAUNCHER_SLEEP & sleep $LAUNCHER_SLEEP" >/dev/null 2>&1 &
timeout_pid=$!
pgid=""
if info=$(wait_for_record_child "$rec"); then
    read -r _ _ pgid _ <<<"$info"
fi
if owned_wait_status "$rec" 600; then
    if [ "${OWNED_LEFTOVERS:-0}" -ge 1 ]; then
        pass "cleanup regression: timed-out descendant observed before release"
    else
        fail "cleanup regression: timed-out descendant observed before release"
    fi
    if pid_matches "$CONTROL_PID" "$CONTROL_START"; then
        pass "cleanup regression: control survives forced-timeout observation"
    else
        fail "cleanup regression: control survives forced-timeout observation"
    fi
    owned_release "$rec"
else
    cleanup_record "$rec" >/dev/null 2>&1 || true
    fail "cleanup regression: timed-out supervisor reported completion"
fi
wait "$timeout_pid"
rc=$?
expect_rc "cleanup regression: forced timeout returns 124" 124 "$rc"
rm -f "$rec" "$rec.status" "$rec.release"
if wait_group_gone "$pgid"; then
    pass "cleanup regression: forced-timeout owned workload and descendants are gone"
else
    fail "cleanup regression: forced-timeout owned workload and descendants are gone" "pgid=$pgid"
fi
if pid_matches "$CONTROL_PID" "$CONTROL_START"; then
    pass "cleanup regression: control survives forced-timeout cleanup"
else
    fail "cleanup regression: control survives forced-timeout cleanup"
fi

# Early-failure path: invoke the suite's real cleanup_record while an owned
# workload is still running. A pipeline (not '&') keeps a second process alive
# without needing /dev/null, which the busybox rootfs does not have.
rec=$(new_record)
owned_start "$rec" "$HUSK" run --rootfs "$ROOTFS" -- \
    /bin/sh -c "sleep $LAUNCHER_SLEEP | sleep $LAUNCHER_SLEEP" >/dev/null 2>&1
early_pid=$OWNED_PID
if info=$(wait_for_record_child "$rec"); then
    read -r early_owner early_start early_pgid early_child <<<"$info"
    others=$(group_others "$early_pgid" "$early_owner")
    if [ -n "$others" ]; then
        pass "cleanup regression: early-failure workload was running before cleanup ($others)"
    else
        fail "cleanup regression: early-failure workload was running before cleanup"
    fi
    if cleanup_record "$rec"; then
        pass "cleanup regression: early-failure cleanup accepted the verified owner"
    else
        fail "cleanup regression: early-failure cleanup accepted the verified owner"
    fi
    if wait_group_gone "$early_pgid"; then
        pass "cleanup regression: early-failure cleanup removed owned workload and descendants"
    else
        fail "cleanup regression: early-failure cleanup removed owned workload and descendants" "pgid=$early_pgid"
    fi
    if pid_matches "$CONTROL_PID" "$CONTROL_START"; then
        pass "cleanup regression: control survives early-failure cleanup"
    else
        fail "cleanup regression: control survives early-failure cleanup"
    fi
else
    kill -KILL "$early_pid" 2>/dev/null || true
    wait "$early_pid" 2>/dev/null || true
    cleanup_record "$rec" >/dev/null 2>&1 || true
    fail "cleanup regression: early-failure workload published its ownership record"
fi

# Deliberate-leak negative control: tests/leaky_helper.c forks a child that
# outlives the helper and prints that child's PID. The same pre-cleanup
# verdict used by the runtime tests must report the leak, and only then may
# emergency cleanup remove it. This is test-owned and never invokes husk, so
# it cannot manufacture a runtime-cleanup failure.
rec=$(new_record)
owned_start "$rec" "$LEAK_HELPER" >"$WORK/leaky-helper.out" 2>&1
leak_pid=$OWNED_PID
pgid=""
if info=$(wait_for_record_child "$rec"); then
    read -r _ _ pgid _ <<<"$info"
fi
if owned_wait_status "$rec"; then
    leaked_child=$(cat "$WORK/leaky-helper.out")
    if [ "${OWNED_LEFTOVERS:-0}" -ge 1 ]; then
        pass "negative control: dedicated leak helper left a process before cleanup"
    else
        fail "negative control: dedicated leak helper left a process before cleanup" \
             "count=${OWNED_LEFTOVERS:-unknown}"
    fi
    case " ${OWNED_LEFTOVER_PIDS:-} " in
        *" ${leaked_child:-none} "*)
            if pid_in_group "$leaked_child" "$pgid"; then
                pass "negative control: leaked helper child is a live owned group member"
            else
                fail "negative control: leaked helper child is a live owned group member" \
                     "pid=$leaked_child pgid=$pgid"
            fi
            ;;
        *)
            fail "negative control: leaked helper child is a live owned group member" \
                 "reported=$leaked_child observed='${OWNED_LEFTOVER_PIDS:-}' pgid=$pgid"
            ;;
    esac
    if owned_cleanup_verdict; then
        fail "negative control: runtime-cleanup assertion failed before cleanup" \
             "verdict was unexpectedly clean"
    else
        pass "negative control: runtime-cleanup assertion failed before cleanup"
    fi
    owned_release "$rec"
    owned_finish "$rec" "$leak_pid" >/dev/null 2>&1
    if wait_group_gone "$pgid"; then
        pass "negative control: emergency cleanup removed the owned helper child"
    else
        fail "negative control: emergency cleanup removed the owned helper child" "pgid=$pgid"
    fi
else
    cleanup_record "$rec" >/dev/null 2>&1 || true
    fail "negative control: leak supervisor reported completion"
fi

# Explicitly terminate and reap the control through its recorded ownership.
if pid_matches "$CONTROL_PID" "$CONTROL_START"; then
    kill -TERM "$CONTROL_PID" 2>/dev/null || true
fi
wait "$CONTROL_PID" 2>/dev/null || true
if pid_matches "$CONTROL_PID" "$CONTROL_START"; then
    fail "cleanup regression: control terminated and reaped"
else
    pass "cleanup regression: control terminated and reaped"
fi
CONTROL_PID=""
CONTROL_START=""


echo "== Ownership verification and stale records =="

# The control is a genuine owned supervisor with a live sleep child. A forged
# record points at that control group but carries a mismatched owner start
# time. cleanup_record must refuse to signal anything. No PID recycling is
# involved: only test-owned processes and a deliberately wrong record.
control_rec=$(new_record)
owned_start "$control_rec" /bin/sleep "$LAUNCHER_SLEEP" >/dev/null 2>&1
control_owner=$OWNED_PID
if info=$(wait_for_record_child "$control_rec"); then
    read -r ctl_owner ctl_start ctl_pgid ctl_child <<<"$info"
    if pid_matches "$ctl_owner" "$ctl_start"; then
        pass "stale-record control is live and anchors its group"
    else
        fail "stale-record control is live and anchors its group"
    fi

    stale_rec=$(new_record)
    printf '%s %s %s %s\n' "$ctl_owner" "$((ctl_start + 1))" "$ctl_pgid" "$ctl_child" \
        >"$stale_rec"
    stale_err=$(cleanup_record "$stale_rec" 2>&1)
    stale_rc=$?
    if [ "$stale_rc" -ne 0 ]; then
        pass "cleanup refuses a mismatched owner start time"
    else
        fail "cleanup refuses a mismatched owner start time"
    fi
    case "$stale_err" in
        *"refusing to signal"*)
            pass "stale-record refusal names the unverified group" ;;
        *)
            fail "stale-record refusal names the unverified group" "got '$stale_err'" ;;
    esac
    if [ ! -e "$stale_rec" ] && [ -e "$stale_rec.unverified" ]; then
        pass "mismatched record is quarantined instead of retried"
    else
        fail "mismatched record is quarantined instead of retried" \
             "record=$([ -e "$stale_rec" ] && echo present || echo gone), quarantine=$([ -e "$stale_rec.unverified" ] && echo present || echo gone)"
    fi
    if pid_matches "$ctl_owner" "$ctl_start"; then
        pass "control survives mismatched-record cleanup"
    else
        fail "control survives mismatched-record cleanup"
    fi

    malformed_rec=$(new_record)
    printf 'not a valid ownership record\n' >"$malformed_rec"
    if ! cleanup_record "$malformed_rec" >/dev/null 2>&1; then
        pass "cleanup rejects a malformed record"
    else
        fail "cleanup rejects a malformed record"
    fi
    if pid_matches "$ctl_owner" "$ctl_start"; then
        pass "control survives malformed-record cleanup"
    else
        fail "control survives malformed-record cleanup"
    fi

    wronggrp_rec=$(new_record)
    printf '%s %s %s %s\n' "$ctl_owner" "$ctl_start" "$((ctl_pgid + 1))" "$ctl_child" \
        >"$wronggrp_rec"
    if ! cleanup_record "$wronggrp_rec" >/dev/null 2>&1; then
        pass "cleanup rejects a record whose PGID is not the owner"
    else
        fail "cleanup rejects a record whose PGID is not the owner"
    fi
    if pid_matches "$ctl_owner" "$ctl_start"; then
        pass "control survives invalid-group-record cleanup"
    else
        fail "control survives invalid-group-record cleanup"
    fi

    if cleanup_record "$control_rec"; then
        pass "cleanup accepts the verified control owner"
    else
        fail "cleanup accepts the verified control owner"
    fi
    if pid_matches "$ctl_owner" "$ctl_start"; then
        fail "stale-record control terminated and reaped"
    else
        pass "stale-record control terminated and reaped"
    fi
else
    cleanup_record "$control_rec" >/dev/null 2>&1 || true
    fail "stale-record control published its ownership record"
fi

echo "== Concurrent ownership records =="

rec_a=$(new_record)
rec_b=$(new_record)
if [ -n "$rec_a" ] && [ -n "$rec_b" ] && [ "$rec_a" != "$rec_b" ]; then
    pass "two outstanding invocations get distinct records"
else
    fail "two outstanding invocations get distinct records" "$rec_a vs $rec_b"
fi

if [ -f "$rec_a" ] && [ -f "$rec_b" ]; then
    pass "both record files exist independently"
else
    fail "both record files exist independently"
fi

owned_start "$rec_a" /bin/sleep "$LAUNCHER_SLEEP" >/dev/null 2>&1
concurrent_a_pid=$OWNED_PID
owned_start "$rec_b" /bin/sleep "$LAUNCHER_SLEEP" >/dev/null 2>&1
concurrent_b_pid=$OWNED_PID
info_a=$(wait_for_record_child "$rec_a")
info_b=$(wait_for_record_child "$rec_b")
if [ -n "$info_a" ] && [ -n "$info_b" ]; then
    read -r own_a start_a pgid_a child_a <<<"$info_a"
    read -r own_b start_b pgid_b child_b <<<"$info_b"
    if [ "$own_a" != "$own_b" ] && [ "$pgid_a" != "$pgid_b" ]; then
        pass "concurrent records hold distinct owner and group IDs"
    else
        fail "concurrent records hold distinct owner and group IDs"
    fi
    if pid_matches "$own_a" "$start_a" && pid_matches "$own_b" "$start_b"; then
        pass "both concurrent supervisors are alive before cleanup"
    else
        fail "both concurrent supervisors are alive before cleanup"
    fi

    if cleanup_record "$rec_a"; then
        pass "cleanup of the first record succeeds"
    else
        fail "cleanup of the first record succeeds"
    fi
    if pid_matches "$own_b" "$start_b"; then
        pass "cleaning one record leaves the other invocation alive"
    else
        fail "cleaning one record leaves the other invocation alive"
    fi
    if [ ! -e "$rec_a" ] && [ -e "$rec_b" ]; then
        pass "only the cleaned record was removed"
    else
        fail "only the cleaned record was removed"
    fi

    if cleanup_record "$rec_b"; then
        pass "cleanup of the second record succeeds"
    else
        fail "cleanup of the second record succeeds"
    fi
    if [ ! -e "$rec_a" ] && [ ! -e "$rec_b" ]; then
        pass "both concurrent records were removed"
    else
        fail "both concurrent records were removed"
    fi
    if ! pid_matches "$own_a" "$start_a" && ! pid_matches "$own_b" "$start_b"; then
        pass "both concurrent supervisors terminated and were reaped"
    else
        fail "both concurrent supervisors terminated and were reaped"
    fi
    if wait_group_gone "$pgid_a" && wait_group_gone "$pgid_b"; then
        pass "both concurrent owned groups are empty"
    else
        fail "both concurrent owned groups are empty"
    fi
else
    cleanup_record "$rec_a" >/dev/null 2>&1 || true
    cleanup_record "$rec_b" >/dev/null 2>&1 || true
    fail "concurrent invocations published their ownership records"
fi

echo "== Repeated launches and leftover resources =="

repeated_ok=1
for _ in $(seq 1 20); do
    rec=$(new_record)
    owned_start "$rec" "$HUSK" run --rootfs "$ROOTFS" -- /bin/true >/dev/null 2>&1
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
[ "$repeated_ok" -eq 1 ] && pass "20 repeated owned launches left no owned leftovers before cleanup" || fail "20 repeated owned launches left no owned leftovers before cleanup"

if grep -qF "$ROOTFS" /proc/self/mountinfo; then
    fail "no mounts from the container leaked to the host"
else
    pass "no mounts from the container leaked to the host"
fi
if [ -e "$ROOTFS/.oldroot" ]; then
    fail "no .oldroot left in rootfs"
else
    pass "no .oldroot left in rootfs"
fi

rm -f "$WORK"/*.err "$WORK"/*.out "$WORK/help.txt"

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
