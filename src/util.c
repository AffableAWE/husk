#define _GNU_SOURCE

#include "husk.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

int husk_send_msg(int fd, uint32_t type, int error, const char *fmt, ...)
{
    struct husk_msg msg;
    va_list ap;
    ssize_t n;

    memset(&msg, 0, sizeof(msg));
    msg.type = type;
    msg.error = error;

    va_start(ap, fmt);
    (void)vsnprintf(msg.text, sizeof(msg.text), fmt, ap);
    va_end(ap);

    do {
        n = send(fd, &msg, sizeof(msg), MSG_NOSIGNAL);
    } while (n < 0 && errno == EINTR);
    /* The parent may already be gone; the child still has to exit cleanly. */
    return (size_t)n == sizeof(msg) ? 0 : -1;
}

int husk_recv_msg(int fd, struct husk_msg *msg)
{
    ssize_t n;

    do {
        n = recv(fd, msg, sizeof(*msg), 0);
    } while (n < 0 && errno == EINTR);

    if (n == 0)
        return 0;
    if (n < 0)
        return -1;
    if ((size_t)n != sizeof(*msg))
        return -1;
    msg->text[sizeof(msg->text) - 1] = '\0';
    return 1;
}

void husk_close_fds_from(int lowfd, unsigned int flags)
{
#ifdef SYS_close_range
    if (syscall(SYS_close_range, (unsigned int)lowfd, ~0U, flags) == 0)
        return;
#endif
    /* Fallback for old kernels: the MVP already closed inherited descriptors
     * in the parent, so this only matters on unusual hosts. */
    {
        long max = sysconf(_SC_OPEN_MAX);
        int fd;

        if (max < 0 || max > 65536)
            max = 65536;
        for (fd = lowfd; fd < (int)max; fd++) {
            if (flags & CLOSE_RANGE_CLOEXEC)
                (void)fcntl(fd, F_SETFD, FD_CLOEXEC);
            else
                (void)close(fd);
        }
    }
}

#ifdef HUSK_TEST_HOOKS
/* Test-only phase markers and release gates. Compiled only when the
 * handshake-lifecycle test binary is built explicitly with -DHUSK_TEST_HOOKS;
 * the normal husk build has no test hooks. */
static void test_hook_path(char *path, size_t pathlen, const char *name,
                           const char *suffix)
{
    const char *dir = getenv("HUSK_TEST_DIR");
    int n;

    path[0] = '\0';
    if (dir == NULL || dir[0] == '\0')
        return;
    n = snprintf(path, pathlen, "%s/%s%s", dir, name, suffix);
    if (n < 0 || (size_t)n >= pathlen)
        path[0] = '\0';
}

static void test_hook_write(const char *name, const char *text)
{
    char path[PATH_MAX];
    size_t len = strlen(text);
    int fd;

    test_hook_path(path, sizeof(path), name, "");
    if (path[0] == '\0')
        return;
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0)
        return;
    if (write(fd, text, len) < 0) { /* best effort */ }
    (void)close(fd);
}

void husk_perf_mark(int phase)
{
    const char *path = getenv("HUSK_PERF_FILE");
    struct timespec ts;
    char buf[128];
    int fd;
    int n;

    if (path == NULL || path[0] == '\0')
        return;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0)
        return;
    fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0)
        return;
    n = snprintf(buf, sizeof(buf), "%d %lld\n", phase,
                 (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec);
    if (n > 0)
        if (write(fd, buf, (size_t)n) < 0) { /* best effort */ }
    close(fd);
}

int husk_test_fail_if(const char *phase)
{
    const char *want = getenv("HUSK_TEST_FAIL_PHASE");

    if (want != NULL && strcmp(want, phase) == 0) {
        husk_test_mark(phase, "injected");
        return 1;
    }
    return 0;
}

void husk_test_mark(const char *name, const char *fmt, ...)
{
    char text[HUSK_CTRL_TEXT];
    va_list ap;

    va_start(ap, fmt);
    (void)vsnprintf(text, sizeof(text), fmt, ap);
    va_end(ap);
    test_hook_write(name, text);
}

static void test_noop_signal(int sig)
{
    (void)sig;
}

/* Test-only: make SIGUSR1 interrupt poll without restarting, so the deadline
 * tests can prove an EINTR does not extend the timeout. Failure-only test
 * paths exit before the normal forwarding path is used. */
void husk_test_interruptible_wait(void)
{
    const char *want = getenv("HUSK_TEST_INTERRUPT_WAIT");
    struct sigaction sa;
    sigset_t set;

    if (want == NULL || want[0] == '\0')
        return;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = test_noop_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    (void)sigaction(SIGUSR1, &sa, NULL);
    sigemptyset(&set);
    sigaddset(&set, SIGUSR1);
    (void)sigprocmask(SIG_UNBLOCK, &set, NULL);
}

void husk_test_wait_release(const char *name, const char *fmt, ...)
{
    const char *want = getenv("HUSK_TEST_PHASE");
    char release[PATH_MAX];
    char text[HUSK_CTRL_TEXT];
    va_list ap;
    int waited;

    if (want == NULL || strcmp(want, name) != 0)
        return;

    va_start(ap, fmt);
    (void)vsnprintf(text, sizeof(text), fmt, ap);
    va_end(ap);
    test_hook_write(name, text);

    test_hook_path(release, sizeof(release), name, ".release");
    if (release[0] == '\0')
        return;

    for (waited = 0; waited < 60000; waited += 10) {
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 10000000L};

        if (access(release, F_OK) == 0)
            return;
        while (nanosleep(&ts, &ts) < 0 && errno == EINTR)
            continue;
    }
}
#endif
