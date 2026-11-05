/* Test-only wrapper: make /proc invisible to a rootless husk invocation.
 *
 * It creates a user+mount namespace, maps inside UID/GID 1 to the invoking
 * user (so husk still sees a nonzero EUID and proceeds), then overmounts /proc
 * with a private tmpfs. Husk's parent-side mapping files under
 * /proc/<child>/uid_map therefore do not exist and the bounded mapping
 * handshake must fail cleanly and reap the child.
 *
 * The mount is in this wrapper's private mount namespace. The host mount
 * namespace is not changed.
 *
 * Usage: no_proc_rootless_wrapper PROGRAM [ARG...]
 */
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <unistd.h>

static int write_file(const char *path, const char *data)
{
    size_t len = strlen(data);
    ssize_t n;
    int fd;

    fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "no_proc_rootless_wrapper: open %s: %s\n", path,
                strerror(errno));
        return -1;
    }
    do {
        n = write(fd, data, len);
    } while (n < 0 && errno == EINTR);
    if (n < 0) {
        fprintf(stderr, "no_proc_rootless_wrapper: write %s: %s\n", path,
                strerror(errno));
        close(fd);
        return -1;
    }
    close(fd);
    return (size_t)n == len ? 0 : -1;
}

int main(int argc, char **argv)
{
    char map[64];
    uid_t host_uid;
    gid_t host_gid;
    int n;

    if (argc < 2) {
        fprintf(stderr, "usage: %s PROGRAM [ARG...]\n", argv[0]);
        return 2;
    }
    host_uid = getuid();
    host_gid = getgid();

    if (unshare(CLONE_NEWUSER | CLONE_NEWNS) < 0) {
        perror("no_proc_rootless_wrapper: unshare");
        return 111;
    }

    /* Map inside 1 (not 0) to the host user. This keeps husk's EUID nonzero so
     * its --rootless guard is satisfied while the host identity stays
     * unprivileged. */
    n = snprintf(map, sizeof(map), "1 %ld 1\n", (long)host_uid);
    if (n < 0 || (size_t)n >= sizeof(map) ||
        write_file("/proc/self/uid_map", map) < 0)
        return 111;
    if (write_file("/proc/self/setgroups", "deny") < 0)
        return 111;
    n = snprintf(map, sizeof(map), "1 %ld 1\n", (long)host_gid);
    if (n < 0 || (size_t)n >= sizeof(map) ||
        write_file("/proc/self/gid_map", map) < 0)
        return 111;

    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0) {
        perror("no_proc_rootless_wrapper: make / private");
        return 111;
    }
    if (mount("tmpfs", "/proc", "tmpfs", MS_NOSUID | MS_NODEV, NULL) < 0) {
        perror("no_proc_rootless_wrapper: mount tmpfs on /proc");
        return 111;
    }

    execv(argv[1], &argv[1]);
    perror("no_proc_rootless_wrapper: execv");
    return 111;
}
