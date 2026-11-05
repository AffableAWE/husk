#!/bin/sh
# Build a small rootfs fixture from a statically linked busybox.
#
# Provenance in the reference environment: Debian bookworm package
# busybox-static (GPL-2.0), installed at /bin/busybox. It is statically linked
# and needs no shared libraries, so the fixture has no libc inside it.
set -eu

root=${1:-build/rootfs}
busybox_bin=${BUSYBOX:-}

mkdir -p "$root/bin" "$root/sbin" "$root/usr/bin" "$root/usr/sbin" \
         "$root/etc" "$root/proc" "$root/dev" "$root/tmp" "$root/root" \
         "$root/var"

# Reuse an installed busybox when the fixture already exists, but still refresh
# the applet symlinks below. That keeps `make check` repeatable after the
# applet list grows.
if [ -x "$root/bin/busybox" ]; then
    echo "reusing busybox already present at $root/bin/busybox"
else
    if [ -z "$busybox_bin" ]; then
        if command -v busybox >/dev/null 2>&1; then
            busybox_bin=$(command -v busybox)
        fi
    fi

    if [ -z "$busybox_bin" ] || [ ! -x "$busybox_bin" ]; then
        echo "error: no busybox found. Install a static busybox, e.g. on Debian:" >&2
        echo "  apt-get install busybox-static" >&2
        echo "or set BUSYBOX=/path/to/static/busybox" >&2
        exit 1
    fi

    echo "busybox: $busybox_bin"
    # Report shared-library requirements; a static busybox prints "not a dynamic
    # executable" (or "statically linked" on some ldd implementations).
    if command -v ldd >/dev/null 2>&1; then
        ldd "$busybox_bin" 2>&1 || true
    fi

    install -m 0755 "$busybox_bin" "$root/bin/busybox"
fi

for applet in sh ls cat echo hostname uname id ps sleep true false env test \
              printf kill awk ping ip nc mount readlink; do
    ln -sf busybox "$root/bin/$applet"
done

chmod 1777 "$root/tmp"
printf 'root:x:0:0:root:/root:/bin/sh\n' > "$root/etc/passwd"
printf 'root:x:0:\n' > "$root/etc/group"

echo "created minimal rootfs at $root"
