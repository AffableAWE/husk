#!/usr/bin/env bash
# Stage 3/4: cgroup v2 controls, cgroup namespace, rlimits, capability policy,
# no_new_privs, and seccomp. Must run as root (privileged mode) or as an
# ordinary user with a delegated cgroup v2 parent (rootless mode).
set -u
set -o pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1
MODE=${HUSK_STAGE34_MODE:-}
CG=${HUSK_CGROUP_PARENT:-}
SOURCE_ROOTFS=${HUSK_ROOTFS:-"$ROOT/build/rootfs"}
HUSK=${HUSK:-"$ROOT/husk"}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/husk-stage34.XXXXXX") || exit 1
ROOTFS="$WORK/rootfs"
OWNED_RUN="$WORK/owned-run"
PASS=0
FAIL=0
SKIP=0
FAILED=()
SKIPPED=()
OWNED_PID=""
REC_OWNER=""
REC_START=""
REC_PGID=""
REC_CHILD=""

usage() { echo "usage: HUSK_STAGE34_MODE=privileged|rootless HUSK_CGROUP_PARENT=DIR $0" >&2; exit 2; }
[ "$MODE" = privileged ] || [ "$MODE" = rootless ] || usage
if [ "$MODE" = rootless ]; then RUN_ARGS=(--rootless); else RUN_ARGS=(); fi
[ -n "$CG" ] || usage
[ -d "$CG" ] || { echo "error: cgroup parent '$CG' missing" >&2; exit 2; }

pass() { PASS=$((PASS+1)); printf 'ok   %s\n' "$1"; }
fail() { FAIL=$((FAIL+1)); FAILED+=("$1"); printf 'FAIL %s: %s\n' "$1" "${2:-}"; }
skip() { SKIP=$((SKIP+1)); SKIPPED+=("$1: $2"); printf 'skip %s: %s\n' "$1" "$2"; }
expect_rc() { if [ "$3" -eq "$2" ]; then pass "$1 (exit $3)"; else fail "$1" "expected $2 got $3"; fi; }

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
    local i rec=$1 owner start pgid child
    for i in $(seq 1 100); do
        if [ -s "$rec" ]; then
            read -r owner start pgid child <"$rec" 2>/dev/null || true
            [ -n "${child:-}" ] && { printf '%s %s %s %s\n' "$owner" "$start" "$pgid" "$child"; return 0; }
        fi
        sleep 0.05
    done
    return 1
}
owned_start() { local rec=$1; shift; "$OWNED_RUN" "$rec" -- "$@" >"$WORK/owned.out" 2>"$WORK/owned.err" & OWNED_PID=$!; }
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
check_leftovers() { if [ "${OWNED_LEFTOVERS:-x}" = 0 ]; then pass "$1 (leftovers=0)"; else fail "$1" "leftovers=${OWNED_LEFTOVERS:-unknown} pids=${OWNED_LEFTOVER_PIDS:-}"; fi; }
cleanup_record() {
    local rec=$1 i
    [ -f "$rec" ] || { rm -f "$rec.status" "$rec.release"; return 0; }
    record_read "$rec" || { mv -f "$rec" "$rec.unverified" 2>/dev/null || rm -f "$rec"; rm -f "$rec.status" "$rec.release"; return 1; }
    pid_matches "$REC_OWNER" "$REC_START" || { mv -f "$rec" "$rec.unverified" 2>/dev/null || rm -f "$rec"; rm -f "$rec.status" "$rec.release"; return 1; }
    : >"$rec.release"; kill -TERM "$REC_OWNER" 2>/dev/null || true
    for i in $(seq 1 50); do pid_matches "$REC_OWNER" "$REC_START" || break; sleep 0.1; done
    if pid_matches "$REC_OWNER" "$REC_START"; then kill -KILL "$REC_OWNER" 2>/dev/null || true; wait "$REC_OWNER" 2>/dev/null || true; mv -f "$rec" "$rec.unverified" 2>/dev/null || rm -f "$rec"; rm -f "$rec.status" "$rec.release"; return 1; fi
    wait "$REC_OWNER" 2>/dev/null || true
    rm -f "$rec" "$rec.status" "$rec.release"
    return 0
}
cleanup() {
    local rec d
    for rec in "$WORK"/owned-*.record; do [ -e "$rec" ] && cleanup_record "$rec" >/dev/null 2>&1 || true; done
    for d in "$CG"/husk.*; do [ -d "$d" ] && rmdir "$d" 2>/dev/null || true; done
    rm -rf "$WORK"
}
trap cleanup EXIT

[ -x "$HUSK" ] || { echo "error: $HUSK not executable" >&2; exit 1; }
[ -d "$SOURCE_ROOTFS" ] || { echo "error: rootfs missing" >&2; exit 1; }
if [ "$MODE" = privileged ]; then
    [ "$(id -u)" -eq 0 ] || { echo "error: privileged mode needs root" >&2; exit 1; }
    [ -w "$CG" ] || { echo "error: cgroup parent not writable" >&2; exit 1; }
else
    [ "$(id -u)" -ne 0 ] || { echo "error: rootless mode needs non-root" >&2; exit 1; }
    [ -w "$CG" ] || { echo "error: delegated cgroup parent not writable" >&2; exit 1; }
fi

cp -a "$SOURCE_ROOTFS" "$ROOTFS" || exit 1
chmod -R u+rwX "$ROOTFS" || exit 1
if ! "${CC:-cc}" -O2 -g -std=c17 -Wall -Wextra -Werror -Wformat=2 -Wvla -o "$OWNED_RUN" "$ROOT/tests/owned_run.c" 2>"$WORK/owned-build.err"; then
    echo "error: build owned_run: $(cat "$WORK/owned-build.err")" >&2; exit 1
fi
for p in mem_probe pids_probe cpu_probe rlimit_probe seccomp_probe status_probe thread_probe; do
    extra=""
    [ "$p" = thread_probe ] && extra="-pthread"
    if ! "${CC:-cc}" $extra -static -O2 -Wall -Wextra -Werror -o "$ROOTFS/bin/$p" "$ROOT/tests/$p.c" 2>"$WORK/$p.err"; then
        echo "error: build $p: $(cat "$WORK/$p.err")" >&2; exit 1
    fi
done

wait_cg_count() { # count tenths
    local want=$1 limit=${2:-200} i n
    for i in $(seq 1 "$limit"); do
        n=$(find "$CG" -mindepth 1 -maxdepth 1 -type d -name 'husk.*' 2>/dev/null | wc -l)
        [ "$n" -ge "$want" ] && return 0
        sleep 0.05
    done
    return 1
}
one_cg() { find "$CG" -mindepth 1 -maxdepth 1 -type d -name 'husk.*' 2>/dev/null | head -1; }
wait_cg_procs() { # dir count tenths
    local dir=$1 want=$2 limit=${3:-200} i n
    for i in $(seq 1 "$limit"); do
        n=$(grep -c '[0-9]' "$dir/cgroup.procs" 2>/dev/null || true)
        [ "${n:-0}" -ge "$want" ] && return 0
        sleep 0.05
    done
    return 1
}
no_cg_left() { [ -z "$(find "$CG" -mindepth 1 -maxdepth 1 -type d -name 'husk.*' 2>/dev/null)" ]; }
read_cg() { cat "$1/$2" 2>/dev/null || true; }
cg_key() { grep -E "^$2 " "$1/$3" 2>/dev/null | awk '{print $2}'; }
kill_owned() { # record
    record_read "$1" || return 1
    pid_matches "$REC_OWNER" "$REC_START" || return 1
    kill -TERM "$REC_OWNER" 2>/dev/null || true
    return 0
}
hroot() { "$HUSK" run "${RUN_ARGS[@]}" --rootfs "$ROOTFS" "$@"; }

echo "== Stage 3/4 environment =="
if [ "$MODE" = privileged ]; then
    pass "privileged mode runs as UID 0"
else
    pass "rootless mode runs as non-root UID $(id -u)"
fi
if [ -e "$CG/cgroup.controllers" ]; then pass "cgroup v2 parent is present"; else fail "cgroup v2 parent is present"; fi

echo "== Capability policy, no_new_privs, seccomp, cgroup namespace =="
out=$(hroot --cgroup-parent "$CG" --memory-max 16777216 --pids-max 8 --cpu-max 5000 100000 --rlimit-nofile 32 --rlimit-fsize 4096 -- /bin/status_probe 2>&1)
rc=$?
expect_rc "status probe exits 0" 0 "$rc"
printf '%s\n' "$out" >"$WORK/status.out"
nself=$(grep -A10 -- '--self--' "$WORK/status.out" | grep -Ec '^Cap(Inh|Prm|Eff|Bnd|Amb):[[:space:]]+0+$')
[ "$nself" -eq 5 ] &&
    pass "workload capability sets are empty" || fail "workload capability sets are empty (matched $nself/5)" "$(cat "$WORK/status.out")"
grep -A10 -- '--self--' "$WORK/status.out" | grep -q '^NoNewPrivs:[[:space:]]*1$' &&
    pass "workload NoNewPrivs=1" || fail "workload NoNewPrivs=1"
grep -A10 -- '--self--' "$WORK/status.out" | grep -q '^Seccomp:[[:space:]]*2$' &&
    pass "workload Seccomp=2" || fail "workload Seccomp=2"
grep -A10 -- '--init--' "$WORK/status.out" | grep -q '^CapEff:[[:space:]]*0000000000000020$' &&
    pass "init effective set is CAP_KILL only" || fail "init effective set is CAP_KILL only"
grep -A10 -- '--init--' "$WORK/status.out" | grep -q '^CapInh:[[:space:]]*0000000000000020$' &&
    pass "init inheritable set is CAP_KILL only" || fail "init inheritable set is CAP_KILL only"
grep -A10 -- '--init--' "$WORK/status.out" | grep -q '^CapBnd:[[:space:]]*0000000000000020$' &&
    pass "init bounding set is CAP_KILL only" || fail "init bounding set is CAP_KILL only"
grep -A10 -- '--init--' "$WORK/status.out" | grep -q '^CapAmb:[[:space:]]*0000000000000000$' &&
    pass "init ambient set is empty" || fail "init ambient set is empty"
grep -A10 -- '--init--' "$WORK/status.out" | grep -q '^NoNewPrivs:[[:space:]]*1$' &&
    pass "init NoNewPrivs=1" || fail "init NoNewPrivs=1"
grep -A10 -- '--init--' "$WORK/status.out" | grep -q '^Seccomp:[[:space:]]*2$' &&
    pass "init Seccomp=2" || fail "init Seccomp=2"
grep -A3 -- '--cgroup--' "$WORK/status.out" | grep -q '0::/' &&
    pass "cgroup namespace reports 0::/" || fail "cgroup namespace reports 0::/"
grep -q '^sys_fs_cgroup=absent$' "$WORK/status.out" &&
    pass "workload has no cgroup2 control mount" || fail "workload has no cgroup2 control mount"
grep -q '^cgroup2_mount=absent$' "$WORK/status.out" &&
    pass "workload mountinfo has no cgroup2 mount" || fail "workload mountinfo has no cgroup2 mount"
sleep 0.3
no_cg_left && pass "status probe cgroup removed after exit" || fail "status probe cgroup removed after exit"
exec 9<"$ROOTFS/etc/passwd"
hroot -- /bin/sh -c 'test ! -e /proc/self/fd/9' >/dev/null 2>&1
fd_rc=$?
exec 9<&-
expect_rc "inherited host fd 9 is closed before workload" 0 "$fd_rc"

echo "== Seccomp forbidden operation =="
out=$(hroot -- /bin/seccomp_probe 2>&1)
rc=$?
expect_rc "seccomp probe exits 0" 0 "$rc"
printf '%s\n' "$out" | grep -q 'ptrace_errno=1' &&
    pass "ptrace is denied with EPERM by seccomp" || fail "ptrace is denied with EPERM by seccomp" "$out"
printf '%s\n' "$out" | grep -q 'ordinary_open_ok' &&
    pass "ordinary file syscalls still succeed" || fail "ordinary file syscalls still succeed" "$out"

echo "== Threads and ordinary child processes =="
out=$(hroot --cgroup-parent "$CG" --pids-max 16 -- /bin/thread_probe 2>&1)
rc=$?
expect_rc "pthread/child probe exits 0" 0 "$rc"
printf '%s\n' "$out" | grep -q 'threads=4 counter=4' &&
    pass "pthread create/join works under seccomp" || fail "pthread create/join works under seccomp" "$out"
printf '%s\n' "$out" | grep -q 'child_exit=7' &&
    pass "ordinary child process exit 7 propagates" || fail "ordinary child process exit 7 propagates" "$out"

echo "== Rlimits =="
out=$(hroot --rlimit-nofile 32 --rlimit-fsize 4096 -- /bin/rlimit_probe 2>&1)
rc=$?
expect_rc "rlimit probe exits 0" 0 "$rc"
printf '%s\n' "$out" | grep -q 'nofile_soft=32 nofile_hard=32' &&
    pass "RLIMIT_NOFILE soft/hard are 32" || fail "RLIMIT_NOFILE soft/hard are 32" "$out"
printf '%s\n' "$out" | grep -q 'fsize_soft=4096 fsize_hard=4096' &&
    pass "RLIMIT_FSIZE soft/hard are 4096" || fail "RLIMIT_FSIZE soft/hard are 4096" "$out"
open_count=$(printf '%s\n' "$out" | sed -n 's/^open_count=\([0-9]*\).*/\1/p')
if [ -n "$open_count" ] && [ "$open_count" -le 32 ] && [ "$open_count" -ge 20 ]; then
    pass "RLIMIT_NOFILE capped open descriptors at $open_count"
else
    fail "RLIMIT_NOFILE capped open descriptors" "count=${open_count:-none}"
fi
fsize_rc=$(printf '%s\n' "$out" | sed -n 's/^fsize_write_rc=\([0-9-]*\).*/\1/p')
if [ -n "$fsize_rc" ] && [ "$fsize_rc" -le 4096 ]; then
    pass "RLIMIT_FSIZE capped the write at $fsize_rc bytes"
else
    fail "RLIMIT_FSIZE capped the write" "rc=${fsize_rc:-none}"
fi

echo "== cgroup limits and live membership =="
rec=$(new_record)
owned_start "$rec" "$HUSK" run "${RUN_ARGS[@]}" --rootfs "$ROOTFS" --cgroup-parent "$CG" --memory-max 16777216 --pids-max 8 --cpu-max 5000 100000 -- /bin/mem_probe 8 20
live_pid=$OWNED_PID
if wait_record "$rec" >/dev/null && wait_cg_count 1 200; then
    cgdir=$(one_cg)
    info=$(wait_record "$rec") || true
    pass "live container cgroup appeared"
    wait_cg_procs "$cgdir" 2 200 || fail "live cgroup membership populated"
    [ "$(read_cg "$cgdir" memory.max)" = "16777216" ] &&
        pass "memory.max is 16777216" || fail "memory.max is 16777216" "$(read_cg "$cgdir" memory.max)"
    [ "$(read_cg "$cgdir" pids.max)" = "8" ] &&
        pass "pids.max is 8" || fail "pids.max is 8" "$(read_cg "$cgdir" pids.max)"
    [ "$(read_cg "$cgdir" cpu.max)" = "5000 100000" ] &&
        pass "cpu.max is 5000 100000" || fail "cpu.max is 5000 100000" "$(read_cg "$cgdir" cpu.max)"
    procs=$(read_cg "$cgdir" cgroup.procs)
    nprocs=$(printf '%s\n' "$procs" | grep -c '[0-9]')
    [ "$nprocs" -ge 2 ] && pass "cgroup holds init and workload ($nprocs PIDs)" || fail "cgroup holds init and workload" "pids=$procs"
    for p in $procs; do
        case "$(cat "/proc/$p/cgroup" 2>/dev/null)" in *"${cgdir##*/}"*) ;; *) fail "PID $p belongs to the container cgroup";; esac
    done
    cur=$(read_cg "$cgdir" memory.current)
    mx=$(read_cg "$cgdir" memory.max)
    if [ -n "$cur" ] && [ -n "$mx" ] && [ "$cur" -le "$mx" ]; then
        pass "memory.current ($cur) <= memory.max ($mx)"
    else
        fail "memory.current <= memory.max" "current=${cur:-none} max=${mx:-none}"
    fi
    kill_owned "$rec" || fail "stop live container"
    if owned_wait_status "$rec" 400; then
        check_leftovers "live container left no owned leftovers"
        [ -n "${OWNED_LEFTOVERS:-}" ] && [ "$OWNED_LEFTOVERS" -eq 0 ] && pass "live container exited" || true
        owned_release "$rec"; owned_finish "$rec" "$live_pid" >/dev/null 2>&1
    else
        cleanup_record "$rec" >/dev/null 2>&1 || true
        fail "live container reported completion"
    fi
    sleep 0.3
    no_cg_left && pass "live container cgroup removed" || fail "live container cgroup removed"
else
    cleanup_record "$rec" >/dev/null 2>&1 || true
    fail "live container cgroup setup"
fi

echo "== Pids enforcement =="
rec=$(new_record)
owned_start "$rec" "$HUSK" run "${RUN_ARGS[@]}" --rootfs "$ROOTFS" --cgroup-parent "$CG" --pids-max 8 -- /bin/pids_probe 20
live_pid=$OWNED_PID
if wait_record "$rec" >/dev/null && wait_cg_count 1 200; then
    cgdir=$(one_cg)
    wait_cg_procs "$cgdir" 2 200 >/dev/null 2>&1 || true
    sleep 1
    cur=$(read_cg "$cgdir" pids.current)
    [ "$cur" = "8" ] && pass "pids.current reached 8" || fail "pids.current reached 8" "got ${cur:-none}"
    ev=$(cg_key "$cgdir" max pids.events)
    [ -n "$ev" ] && [ "$ev" -gt 0 ] && pass "pids.events max counted $ev fork denials" || fail "pids.events max counted denials" "got ${ev:-none}"
    printf '%s\n' "$(cat "$WORK/owned.out")" | grep -Eq 'forked=[0-9]+ failed=[1-9]' &&
        pass "pids probe observed fork denials" || fail "pids probe observed fork denials" "$(cat "$WORK/owned.out")"
    kill_owned "$rec" || fail "stop pids container"
    if owned_wait_status "$rec" 400; then
        check_leftovers "pids container left no owned leftovers"
        owned_release "$rec"; owned_finish "$rec" "$live_pid" >/dev/null 2>&1
    else cleanup_record "$rec" >/dev/null 2>&1 || true; fail "pids container reported completion"; fi
    sleep 0.3
    no_cg_left && pass "pids container cgroup removed" || fail "pids container cgroup removed"
else cleanup_record "$rec" >/dev/null 2>&1 || true; fail "pids container cgroup setup"; fi

echo "== CPU enforcement =="
rec=$(new_record)
owned_start "$rec" "$HUSK" run "${RUN_ARGS[@]}" --rootfs "$ROOTFS" --cgroup-parent "$CG" --cpu-max 5000 100000 -- /bin/cpu_probe 5
live_pid=$OWNED_PID
if wait_record "$rec" >/dev/null && wait_cg_count 1 200; then
    cgdir=$(one_cg)
    wait_cg_procs "$cgdir" 2 200 >/dev/null 2>&1 || true
    sleep 2
    nr=$(grep '^nr_throttled ' "$cgdir/cpu.stat" 2>/dev/null | awk '{print $2}')
    th=$(grep '^throttled_usec ' "$cgdir/cpu.stat" 2>/dev/null | awk '{print $2}')
    use=$(grep '^usage_usec ' "$cgdir/cpu.stat" 2>/dev/null | awk '{print $2}')
    [ -n "$nr" ] && [ "$nr" -gt 0 ] && pass "cpu.stat reports throttling ($nr periods)" || fail "cpu.stat reports throttling" "nr=${nr:-none}"
    [ -n "$th" ] && [ "$th" -gt 0 ] && pass "cpu.stat throttled_usec=$th" || fail "cpu.stat throttled_usec" "got ${th:-none}"
    [ -n "$use" ] && [ "$use" -lt 500000 ] && pass "cpu usage was capped (usage_usec=$use)" || fail "cpu usage was capped" "usage=${use:-none}"
    kill_owned "$rec" || fail "stop CPU container"
    if owned_wait_status "$rec" 400; then
        check_leftovers "CPU container left no owned leftovers"
        owned_release "$rec"; owned_finish "$rec" "$live_pid" >/dev/null 2>&1
    else cleanup_record "$rec" >/dev/null 2>&1 || true; fail "CPU container reported completion"; fi
    sleep 0.3
    no_cg_left && pass "CPU container cgroup removed" || fail "CPU container cgroup removed"
else cleanup_record "$rec" >/dev/null 2>&1 || true; fail "CPU container cgroup setup"; fi

echo "== Memory pressure accounting =="
rec=$(new_record)
owned_start "$rec" "$HUSK" run "${RUN_ARGS[@]}" --rootfs "$ROOTFS" --cgroup-parent "$CG" --memory-max 16777216 -- /bin/mem_probe 64 10
live_pid=$OWNED_PID
if wait_record "$rec" >/dev/null && wait_cg_count 1 200; then
    cgdir=$(one_cg)
    wait_cg_procs "$cgdir" 2 200 >/dev/null 2>&1 || true
    sleep 2
    cur=$(read_cg "$cgdir" memory.current)
    mx=$(read_cg "$cgdir" memory.max)
    peak=$(read_cg "$cgdir" memory.peak)
    ev=$(cg_key "$cgdir" max memory.events)
    if [ -n "$cur" ] && [ -n "$mx" ] && [ "$cur" -le "$mx" ]; then pass "memory.current stayed within max ($cur <= $mx)"; else fail "memory.current stayed within max" "cur=${cur:-none} max=${mx:-none}"; fi
    [ -n "$ev" ] && [ "$ev" -gt 0 ] && pass "memory.events max counted $ev limit hits" || fail "memory.events max counted limit hits" "got ${ev:-none}"
    [ -n "$peak" ] && pass "memory.peak=$peak" || fail "memory.peak readable"
    kill_owned "$rec" || fail "stop memory container"
    if owned_wait_status "$rec" 400; then
        check_leftovers "memory container left no owned leftovers"
        owned_release "$rec"; owned_finish "$rec" "$live_pid" >/dev/null 2>&1
    else cleanup_record "$rec" >/dev/null 2>&1 || true; fail "memory container reported completion"; fi
    sleep 0.3
    no_cg_left && pass "memory container cgroup removed" || fail "memory container cgroup removed"
else cleanup_record "$rec" >/dev/null 2>&1 || true; fail "memory container cgroup setup"; fi

echo "== Simultaneous containers =="
rec_a=$(new_record); rec_b=$(new_record)
owned_start "$rec_a" "$HUSK" run "${RUN_ARGS[@]}" --rootfs "$ROOTFS" --cgroup-parent "$CG" --pids-max 8 -- /bin/sleep 20
pid_a=$OWNED_PID
owned_start "$rec_b" "$HUSK" run "${RUN_ARGS[@]}" --rootfs "$ROOTFS" --cgroup-parent "$CG" --pids-max 8 -- /bin/sleep 20
pid_b=$OWNED_PID
if wait_record "$rec_a" >/dev/null && wait_record "$rec_b" >/dev/null && wait_cg_count 2 300; then
    dirs=$(find "$CG" -mindepth 1 -maxdepth 1 -type d -name 'husk.*' | sort)
    na=$(printf '%s\n' "$dirs" | wc -l)
    [ "$na" -ge 2 ] && pass "two simultaneous containers have $na unique cgroups" || fail "two simultaneous containers have unique cgroups"
    [ "$(printf '%s\n' "$dirs" | uniq | wc -l)" -eq "$na" ] && pass "simultaneous cgroups are distinct" || fail "simultaneous cgroups are distinct"
    kill_owned "$rec_a"; kill_owned "$rec_b"
    if owned_wait_status "$rec_a" 500; then
        check_leftovers "simultaneous container A left no owned leftovers"
        owned_release "$rec_a"; owned_finish "$rec_a" "$pid_a" >/dev/null 2>&1
    else fail "simultaneous container A reported completion"; fi
    if owned_wait_status "$rec_b" 500; then
        check_leftovers "simultaneous container B left no owned leftovers"
        owned_release "$rec_b"; owned_finish "$rec_b" "$pid_b" >/dev/null 2>&1
    else fail "simultaneous container B reported completion"; fi
    sleep 0.5
    no_cg_left && pass "simultaneous cgroups removed" || fail "simultaneous cgroups removed"
else cleanup_record "$rec_a" >/dev/null 2>&1 || true; cleanup_record "$rec_b" >/dev/null 2>&1 || true; fail "simultaneous containers started"; fi

echo "== Invalid configuration and rollback =="
"$HUSK" run "${RUN_ARGS[@]}" --rootfs "$ROOTFS" --memory-max 1024 -- /bin/true >/dev/null 2>&1
expect_rc "memory limit without cgroup parent is rejected" 2 $?
"$HUSK" run "${RUN_ARGS[@]}" --rootfs "$ROOTFS" --cgroup-parent "$CG" --memory-max 0 -- /bin/true >/dev/null 2>&1
expect_rc "zero memory.max is rejected" 2 $?
"$HUSK" run "${RUN_ARGS[@]}" --rootfs "$ROOTFS" --cgroup-parent "$CG" --pids-max 0 -- /bin/true >/dev/null 2>&1
expect_rc "zero pids.max is rejected" 2 $?
"$HUSK" run "${RUN_ARGS[@]}" --rootfs "$ROOTFS" --cgroup-parent "$CG" --cpu-max 0 100000 -- /bin/true >/dev/null 2>&1
expect_rc "zero cpu quota is rejected" 2 $?
"$HUSK" run "${RUN_ARGS[@]}" --rootfs "$ROOTFS" --rlimit-nofile 8 -- /bin/true >/dev/null 2>&1
expect_rc "below-minimum RLIMIT_NOFILE is rejected" 2 $?
"$HUSK" run "${RUN_ARGS[@]}" --rootfs "$ROOTFS" --cgroup-parent /no/such/cgroup -- /bin/true >/dev/null 2>&1
expect_rc "missing cgroup parent is rejected" 2 $?
cp -a "$ROOTFS" "$WORK/badrootfs"
rm -rf "$WORK/badrootfs/proc"; : >"$WORK/badrootfs/proc"
"$HUSK" run "${RUN_ARGS[@]}" --rootfs "$WORK/badrootfs" --cgroup-parent "$CG" --memory-max 16777216 -- /bin/true >"$WORK/rollback.out" 2>&1
expect_rc "partial setup with cgroup fails 125" 125 $?
sleep 0.3
no_cg_left && pass "partial setup removed its cgroup" || fail "partial setup removed its cgroup"
if [ "$MODE" = rootless ] && [ -n "${HUSK_DENIED_PARENT:-}" ] && [ -d "$HUSK_DENIED_PARENT" ]; then
    "$HUSK" run --rootless --rootfs "$ROOTFS" --cgroup-parent "$HUSK_DENIED_PARENT" --memory-max 16777216 -- /bin/true >"$WORK/denied.out" 2>&1
    expect_rc "denied cgroup delegation fails 125" 125 $?
    grep -q 'cgroup setup failed' "$WORK/denied.out" && pass "denied delegation leaves an actionable error" || fail "denied delegation leaves an actionable error" "$(cat "$WORK/denied.out")"
else
    skip "denied cgroup delegation" "rootless denied parent not provided"
fi

echo
echo "passed: $PASS, failed: $FAIL, skipped: $SKIP"
if [ "$SKIP" -ne 0 ]; then printf 'skipped checks:\n  - %s\n' "${SKIPPED[@]}"; fi
if [ "$FAIL" -ne 0 ]; then printf 'failed checks:\n  - %s\n' "${FAILED[@]}"; exit 1; fi
exit 0
