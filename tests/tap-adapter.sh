#!/usr/bin/env bash
# Convert the simple "ok / FAIL / skip" logs used by the stage suites into TAP.
set -u
tmp=$(mktemp "${TMPDIR:-/tmp}/husk-tap.XXXXXX") || exit 1
trap 'rm -f "$tmp"' EXIT
n=0
while IFS= read -r line; do
    case "$line" in
        ok\ \ \ *)
            n=$((n+1)); printf 'ok %d - %s\n' "$n" "${line#ok   }" >>"$tmp" ;;
        FAIL\ *)
            n=$((n+1)); rest=${line#FAIL }
            desc=${rest%%:*}; detail=${rest#*: }
            printf 'not ok %d - %s # %s\n' "$n" "$desc" "$detail" >>"$tmp" ;;
        skip\ *)
            n=$((n+1)); rest=${line#skip }
            desc=${rest%%:*}; reason=${rest#*: }
            printf 'ok %d - %s # SKIP %s\n' "$n" "$desc" "$reason" >>"$tmp" ;;
        ===*)
            printf '# %s\n' "$line" >>"$tmp" ;;
    esac
done
echo "TAP version 13"
cat "$tmp"
echo "1..$n"
