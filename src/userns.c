/* Rootless user-namespace mapping handshake.
 *
 * The child is cloned with CLONE_NEWUSER together with the other namespaces.
 * It cannot perform mount, PID, or UTS setup until the parent has installed
 * the UID/GID maps, because until then its credentials are unmapped. The
 * parent and child therefore exchange fixed-size messages over the existing
 * SOCK_SEQPACKET control socket:
 *
 *   child  -> HUSK_MSG_MAP_REQUEST
 *   parent -> HUSK_MSG_MAP_READY  after uid_map, setgroups=deny, and gid_map
 *   parent -> HUSK_MSG_MAP_ERROR  on any mapping failure
 *
 * Both sides bound the exchange. The parent kills and reaps the container init
 * on failure; the child reports a setup error and exits.
 */
#define _GNU_SOURCE

#include "husk.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void set_err(char *err, size_t errlen, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

static void set_err(char *err, size_t errlen, const char *fmt, ...)
{
    va_list ap;

    if (err == NULL || errlen == 0)
        return;
    va_start(ap, fmt);
    (void)vsnprintf(err, errlen, fmt, ap);
    va_end(ap);
}

static void kill_and_reap(pid_t child)
{
    int saved_errno = errno;

    (void)kill(child, SIGKILL);
    while (waitpid(child, NULL, 0) < 0 && errno == EINTR)
        continue;
    errno = saved_errno;
}

/* Map files must be written once, at offset zero, with one write. A partial
 * write is an error: retrying would not be a valid second mapping write. */
static int write_map_file(pid_t child, const char *name, const char *data,
                          bool allow_missing, char *err, size_t errlen)
{
    char path[PATH_MAX];
    size_t len = strlen(data);
    ssize_t n;
    int fd;
    int saved_errno;

    if (snprintf(path, sizeof(path), "/proc/%ld/%s", (long)child, name) >=
        (int)sizeof(path)) {
        set_err(err, errlen, "mapping path for %s is too long", name);
        return -1;
    }

    fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) {
        if (allow_missing && errno == ENOENT)
            return 0;
        set_err(err, errlen, "open %s: %s", path, strerror(errno));
        return -1;
    }

    do {
        n = write(fd, data, len);
    } while (n < 0 && errno == EINTR);
    saved_errno = errno;

    if (n < 0) {
        (void)close(fd);
        set_err(err, errlen, "write %s: %s", path, strerror(saved_errno));
        return -1;
    }
    if ((size_t)n != len) {
        (void)close(fd);
        set_err(err, errlen, "short write to %s (%zd of %zu bytes)", path, n,
                len);
        return -1;
    }
    if (close(fd) < 0) {
        set_err(err, errlen, "close %s: %s", path, strerror(errno));
        return -1;
    }
    return 0;
}

static long long monotonic_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0)
        return 0;
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int map_timeout_error(const char *side, char *err, size_t errlen)
{
    set_err(err, errlen,
            "%s: timed out after %d ms waiting for user namespace mapping",
            side, HUSK_MAP_TIMEOUT_MS);
#ifdef HUSK_TEST_HOOKS
    {
        char phase[32];

        (void)snprintf(phase, sizeof(phase), "%s-map-timeout", side);
        husk_test_mark(phase, "%s", err);
    }
#endif
    return -1;
}

/* Receive one handshake message with a hard upper bound. The bound is an
 * absolute monotonic deadline, so an interrupted wait does not restart the
 * timeout and extend the claimed limit. */
static int recv_bounded(int fd, struct husk_msg *msg, const char *side,
                        char *err, size_t errlen)
{
#ifdef HUSK_TEST_HOOKS
    husk_test_interruptible_wait();
#endif
    long long deadline = monotonic_ms() + HUSK_MAP_TIMEOUT_MS;

    for (;;) {
        struct pollfd pfd = {.fd = fd, .events = POLLIN};
        long long remaining = deadline - monotonic_ms();
        int handled;
        int r;

        if (remaining <= 0)
            return map_timeout_error(side, err, errlen);
        r = poll(&pfd, 1, (int)remaining);
        if (r < 0) {
            if (errno == EINTR) {
#ifdef HUSK_TEST_HOOKS
                char phase[32];

                (void)snprintf(phase, sizeof(phase), "%s-map-eintr", side);
                husk_test_mark(phase, "eintr");
#endif
                continue;
            }
            set_err(err, errlen, "%s: poll mapping socket: %s", side,
                    strerror(errno));
            return -1;
        }
        if (r == 0)
            return map_timeout_error(side, err, errlen);

        handled = husk_recv_msg(fd, msg);
        if (handled == 0) {
            set_err(err, errlen,
                    "%s: control socket closed during user namespace mapping",
                    side);
            return -1;
        }
        if (handled < 0) {
            set_err(err, errlen, "%s: invalid control message during user "
                                 "namespace mapping",
                    side);
            return -1;
        }
        return 0;
    }
}

int husk_userns_parent_map(pid_t child, int ctrl_fd, uid_t host_uid,
                           gid_t host_gid, char *err, size_t errlen)
{
    struct husk_msg msg;
    char map[64];
    int n;

    if (recv_bounded(ctrl_fd, &msg, "parent", err, errlen) < 0) {
        kill_and_reap(child);
        return -1;
    }

    if (msg.type != HUSK_MSG_MAP_REQUEST) {
        if (msg.type == HUSK_MSG_SETUP_ERROR ||
            msg.type == HUSK_MSG_EXEC_ERROR) {
            set_err(err, errlen, "%s",
                    msg.text[0] != '\0' ? msg.text
                                        : "container init failed before the "
                                          "user namespace mapping request");
        } else {
            set_err(err, errlen,
                    "unexpected control message type %u during user namespace "
                    "mapping",
                    msg.type);
        }
        kill_and_reap(child);
        return -1;
    }

#ifdef HUSK_TEST_HOOKS
    husk_test_wait_release("parent-map-request", "%ld", (long)child);
#endif

    /* The parent is in the child's parent user namespace and owns the child
     * namespace, so it may write these one-time mapping files. Keep the
     * ordering required for an unprivileged writer: uid_map first, then
     * setgroups=deny, then gid_map. */
    n = snprintf(map, sizeof(map), "0 %ld 1\n", (long)host_uid);
    if (n < 0 || (size_t)n >= sizeof(map)) {
        set_err(err, errlen, "UID map is too long");
        goto fail;
    }
    if (write_map_file(child, "uid_map", map, false, err, errlen) < 0)
        goto fail;

    if (write_map_file(child, "setgroups", "deny", true, err, errlen) < 0)
        goto fail;

    n = snprintf(map, sizeof(map), "0 %ld 1\n", (long)host_gid);
    if (n < 0 || (size_t)n >= sizeof(map)) {
        set_err(err, errlen, "GID map is too long");
        goto fail;
    }
    if (write_map_file(child, "gid_map", map, false, err, errlen) < 0)
        goto fail;

    if (husk_send_msg(ctrl_fd, HUSK_MSG_MAP_READY, 0, "mapped") < 0) {
        set_err(err, errlen, "send user namespace mapping acknowledgement: %s",
                strerror(errno));
        goto fail;
    }
    return 0;

fail:
    /* Tell the child why the mapping failed when it is still listening; the
     * kill below guarantees cleanup even if the message cannot be delivered. */
    (void)husk_send_msg(ctrl_fd, HUSK_MSG_MAP_ERROR, HUSK_EXIT_SETUP, "%s",
                        err != NULL ? err : "user namespace mapping failed");
    kill_and_reap(child);
    return -1;
}

int husk_userns_child_wait(int ctrl_fd, char *err, size_t errlen)
{
    struct husk_msg msg;

#ifdef HUSK_TEST_HOOKS
    husk_test_wait_release("child-before-map-request", "reached");
#endif

    if (husk_send_msg(ctrl_fd, HUSK_MSG_MAP_REQUEST, 0, "request") < 0) {
        set_err(err, errlen, "send user namespace mapping request: %s",
                strerror(errno));
        return -1;
    }
#ifdef HUSK_TEST_HOOKS
    husk_test_mark("child-map-request-sent", "reached");
#endif

    if (recv_bounded(ctrl_fd, &msg, "child", err, errlen) < 0)
        return -1;

    if (msg.type == HUSK_MSG_MAP_READY)
        return 0;

    if (msg.type == HUSK_MSG_MAP_ERROR) {
        set_err(err, errlen, "%s",
                msg.text[0] != '\0' ? msg.text
                                    : "parent rejected user namespace mapping");
        return -1;
    }

    if (msg.type == HUSK_MSG_SETUP_ERROR || msg.type == HUSK_MSG_EXEC_ERROR) {
        set_err(err, errlen, "%s",
                msg.text[0] != '\0' ? msg.text
                                    : "parent reported a setup error during "
                                      "user namespace mapping");
        return -1;
    }

    set_err(err, errlen,
            "unexpected control message type %u during user namespace mapping",
            msg.type);
    return -1;
}
