/* cgroup v2 management and cgroup-namespace setup handshake.
 *
 * The parent creates one unique child cgroup under the explicitly supplied
 * delegated parent, writes and verifies the requested controller limits, then
 * moves the container init into it. The child waits for that acknowledgement
 * before unsharing its cgroup namespace, so the namespace root is the
 * container cgroup. The cgroup is removed after the init exits (or after a
 * setup failure).
 */
#define _GNU_SOURCE

#include "husk.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
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

static int read_text(const char *path, char *buf, size_t buflen)
{
    ssize_t n;
    int fd;

    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    do {
        n = read(fd, buf, buflen - 1);
    } while (n < 0 && errno == EINTR);
    (void)close(fd);
    if (n < 0)
        return -1;
    buf[n] = '\0';
    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r'))
        buf[--n] = '\0';
    return 0;
}

static int write_text(const char *path, const char *text)
{
    size_t len = strlen(text);
    ssize_t n;
    int fd;
    int saved;

    fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    do {
        n = write(fd, text, len);
    } while (n < 0 && errno == EINTR);
    saved = errno;
    if (close(fd) < 0 && n >= 0)
        return -1;
    if (n < 0) {
        errno = saved;
        return -1;
    }
    return (size_t)n == len ? 0 : -1;
}

static int contains_token(const char *text, const char *token)
{
    size_t len = strlen(token);
    const char *p = text;

    while (*p != '\0') {
        while (*p == ' ' || *p == '\t' || *p == '\n')
            p++;
        if (strncmp(p, token, len) == 0 &&
            (p[len] == '\0' || p[len] == ' ' || p[len] == '\t' ||
             p[len] == '\n'))
            return 1;
        while (*p != '\0' && *p != ' ' && *p != '\t' && *p != '\n')
            p++;
    }
    return 0;
}

static int enable_controllers(const char *parent, const struct husk_config *cfg,
                              char *err, size_t errlen)
{
    char path[PATH_MAX];
    char controllers[512];
    char subtree[512];
    char add[64] = "";
    const char *need[3];
    size_t nneed = 0;
    size_t i;

    if (!cfg->memory_set && !cfg->pids_set && !cfg->cpu_set)
        return 0;

    if (snprintf(path, sizeof(path), "%s/cgroup.controllers", parent) >=
        (int)sizeof(path)) {
        set_err(err, errlen, "cgroup parent path is too long");
        return -1;
    }
    if (read_text(path, controllers, sizeof(controllers)) < 0) {
        set_err(err, errlen, "read cgroup.controllers in '%s': %s", parent,
                strerror(errno));
        return -1;
    }
    if (cfg->memory_set)
        need[nneed++] = "memory";
    if (cfg->pids_set)
        need[nneed++] = "pids";
    if (cfg->cpu_set)
        need[nneed++] = "cpu";

    for (i = 0; i < nneed; i++) {
        if (!contains_token(controllers, need[i])) {
            set_err(err, errlen,
                    "cgroup controller '%s' is not available in parent '%s' "
                    "(delegation does not include it)",
                    need[i], parent);
            return -1;
        }
    }

    if (snprintf(path, sizeof(path), "%s/cgroup.subtree_control", parent) >=
        (int)sizeof(path)) {
        set_err(err, errlen, "cgroup parent path is too long");
        return -1;
    }
    if (read_text(path, subtree, sizeof(subtree)) < 0) {
        set_err(err, errlen, "read cgroup.subtree_control in '%s': %s", parent,
                strerror(errno));
        return -1;
    }
    for (i = 0; i < nneed; i++) {
        if (contains_token(subtree, need[i]))
            continue;
        if (strlen(add) + strlen(need[i]) + 3 >= sizeof(add)) {
            set_err(err, errlen, "cgroup controller request is too long");
            return -1;
        }
        strcat(add, "+");
        strcat(add, need[i]);
        strcat(add, " ");
    }
    if (add[0] != '\0') {
        if (write_text(path, add) < 0) {
            set_err(err, errlen,
                    "cannot enable cgroup controllers in '%s': %s "
                    "(the delegated parent must be empty and writable)",
                    parent, strerror(errno));
            return -1;
        }
        if (read_text(path, subtree, sizeof(subtree)) < 0) {
            set_err(err, errlen, "re-read cgroup.subtree_control: %s",
                    strerror(errno));
            return -1;
        }
        for (i = 0; i < nneed; i++) {
            if (!contains_token(subtree, need[i])) {
                set_err(err, errlen,
                        "cgroup controller '%s' did not become enabled in "
                        "'%s'",
                        need[i], parent);
                return -1;
            }
        }
    }
    return 0;
}

static int verify_memory(const char *path, unsigned long long requested,
                         char *err, size_t errlen)
{
    char buf[64];
    char *end;
    unsigned long long got;
    long page = sysconf(_SC_PAGESIZE);

    if (read_text(path, buf, sizeof(buf)) < 0) {
        set_err(err, errlen, "read %s: %s", path, strerror(errno));
        return -1;
    }
    if (strcmp(buf, "max") == 0) {
        set_err(err, errlen, "memory.max remained 'max' after write");
        return -1;
    }
    errno = 0;
    got = strtoull(buf, &end, 10);
    if (errno != 0 || *end != '\0') {
        set_err(err, errlen, "invalid memory.max readback '%s'", buf);
        return -1;
    }
    /* cgroup v2 rounds memory.max down to the page size. */
    if (got > requested ||
        (page > 0 && requested > (unsigned long long)page &&
         got < requested - (unsigned long long)page)) {
        set_err(err, errlen,
                "memory.max readback %llu does not match requested %llu",
                got, requested);
        return -1;
    }
    return 0;
}

static int verify_exact(const char *path, const char *expected, char *err,
                        size_t errlen)
{
    char buf[128];

    if (read_text(path, buf, sizeof(buf)) < 0) {
        set_err(err, errlen, "read %s: %s", path, strerror(errno));
        return -1;
    }
    if (strcmp(buf, expected) != 0) {
        set_err(err, errlen, "%s readback '%s' != requested '%s'", path, buf,
                expected);
        return -1;
    }
    return 0;
}

static int configure_limits(const char *path, const struct husk_config *cfg,
                            char *err, size_t errlen)
{
    char file[PATH_MAX];
    char value[64];

    if (cfg->memory_set) {
        if (snprintf(file, sizeof(file), "%s/memory.max", path) >=
            (int)sizeof(file)) {
            set_err(err, errlen, "cgroup path is too long");
            return -1;
        }
        (void)snprintf(value, sizeof(value), "%llu", cfg->memory_max);
        if (write_text(file, value) < 0) {
            set_err(err, errlen, "write memory.max=%s: %s", value,
                    strerror(errno));
            return -1;
        }
        if (verify_memory(file, cfg->memory_max, err, errlen) < 0)
            return -1;
    }
    if (cfg->pids_set) {
        if (snprintf(file, sizeof(file), "%s/pids.max", path) >=
            (int)sizeof(file)) {
            set_err(err, errlen, "cgroup path is too long");
            return -1;
        }
        (void)snprintf(value, sizeof(value), "%llu", cfg->pids_max);
        if (write_text(file, value) < 0) {
            set_err(err, errlen, "write pids.max=%s: %s", value,
                    strerror(errno));
            return -1;
        }
        if (verify_exact(file, value, err, errlen) < 0)
            return -1;
    }
    if (cfg->cpu_set) {
        if (snprintf(file, sizeof(file), "%s/cpu.max", path) >=
            (int)sizeof(file)) {
            set_err(err, errlen, "cgroup path is too long");
            return -1;
        }
        (void)snprintf(value, sizeof(value), "%llu %llu", cfg->cpu_quota,
                       cfg->cpu_period);
        if (write_text(file, value) < 0) {
            set_err(err, errlen, "write cpu.max='%s': %s", value,
                    strerror(errno));
            return -1;
        }
        if (verify_exact(file, value, err, errlen) < 0)
            return -1;
    }
    return 0;
}

static unsigned long long self_starttime(void)
{
    char buf[4096];
    char *after;
    char *tok;
    int fd;
    int i;
    ssize_t n;

    fd = open("/proc/self/stat", O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return 0;
    n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0)
        return 0;
    buf[n] = '\0';
    after = strrchr(buf, ')');
    if (after == NULL)
        return 0;
    tok = strtok(after + 1, " ");
    for (i = 0; tok != NULL && i < 19; i++)
        tok = strtok(NULL, " ");
    return tok != NULL ? strtoull(tok, NULL, 10) : 0;
}

static unsigned long long pid_starttime(pid_t pid)
{
    char path[64];
    char buf[4096];
    char *after;
    char *tok;
    int fd;
    int i;
    ssize_t n;

    (void)snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid);
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return 0;
    n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0)
        return 0;
    buf[n] = '\0';
    after = strrchr(buf, ')');
    if (after == NULL)
        return 0;
    tok = strtok(after + 1, " ");
    for (i = 0; tok != NULL && i < 19; i++)
        tok = strtok(NULL, " ");
    return tok != NULL ? strtoull(tok, NULL, 10) : 0;
}

/* Remove cgroups left by a husk parent that died without running cleanup.
 * Names are stamped with the owner PID and starttime, so a reused PID is not
 * mistaken for the owner. Only an empty cgroup with our exact prefix is
 * removed; a populated or unrecognised directory is left alone. */
static int recover_stale_cgroups(const char *parent, char *err, size_t errlen)
{
    DIR *dir;
    struct dirent *de;

    dir = opendir(parent);
    if (dir == NULL) {
        set_err(err, errlen, "scan cgroup parent '%s': %s", parent,
                strerror(errno));
        return -1;
    }
    while ((de = readdir(dir)) != NULL) {
        long pid;
        unsigned long long start;
        char tail[8];
        char path[PATH_MAX];
        char procs[PATH_MAX];
        char buf[4096];

        if (strncmp(de->d_name, "husk.", 5) != 0)
            continue;
        if (sscanf(de->d_name, "husk.%ld.%llu.%7s", &pid, &start, tail) != 3)
            continue;
        if (pid > 1 && pid_starttime((pid_t)pid) == start)
            continue; /* live owner */
        if (snprintf(path, sizeof(path), "%s/%s", parent, de->d_name) >=
            (int)sizeof(path)) {
            set_err(err, errlen, "stale cgroup path is too long");
            closedir(dir);
            return -1;
        }
        if (snprintf(procs, sizeof(procs), "%s/cgroup.procs", path) >=
            (int)sizeof(procs)) {
            set_err(err, errlen, "stale cgroup path is too long");
            closedir(dir);
            return -1;
        }
        if (read_text(procs, buf, sizeof(buf)) < 0)
            continue;
        if (buf[0] != '\0')
            continue; /* do not delete a populated cgroup */
        if (rmdir(path) < 0 && errno != ENOENT) {
            set_err(err, errlen,
                    "remove stale cgroup '%s': %s (empty cgroup required)",
                    path, strerror(errno));
            closedir(dir);
            return -1;
        }
    }
    (void)closedir(dir);
    return 0;
}

int husk_cgroup_create(const char *parent, const struct husk_config *cfg,
                       char *path, size_t pathlen, char *err, size_t errlen)
{
    struct stat st;
    char template_path[PATH_MAX];
    char procs[PATH_MAX];
    char buf[4096];
    int n;

    if (stat(parent, &st) < 0 || !S_ISDIR(st.st_mode)) {
        set_err(err, errlen, "invalid cgroup parent '%s': %s", parent,
                strerror(errno));
        return -1;
    }
    if (snprintf(procs, sizeof(procs), "%s/cgroup.procs", parent) >=
        (int)sizeof(procs) ||
        access(procs, F_OK) < 0) {
        set_err(err, errlen, "'%s' is not a cgroup v2 directory", parent);
        return -1;
    }

    if (recover_stale_cgroups(parent, err, errlen) < 0)
        return -1;
    if (enable_controllers(parent, cfg, err, errlen) < 0)
        return -1;

    n = snprintf(template_path, sizeof(template_path), "%s/husk.%ld.%llu.XXXXXX",
                 parent, (long)getpid(), self_starttime());
    if (n < 0 || (size_t)n >= sizeof(template_path)) {
        set_err(err, errlen, "cgroup parent path is too long");
        return -1;
    }
    if (mkdtemp(template_path) == NULL) {
        set_err(err, errlen, "create cgroup under '%s': %s", parent,
                strerror(errno));
        return -1;
    }
    if (strlen(template_path) + 1 > pathlen) {
        set_err(err, errlen, "cgroup path is too long");
        (void)rmdir(template_path);
        return -1;
    }
    strcpy(path, template_path);

    if (configure_limits(path, cfg, err, errlen) < 0) {
        husk_cgroup_remove(path);
        return -1;
    }
    /* Verify the directory is actually present and usable before cloning. */
    if (snprintf(procs, sizeof(procs), "%s/cgroup.procs", path) >=
            (int)sizeof(procs) ||
        read_text(procs, buf, sizeof(buf)) < 0) {
        set_err(err, errlen, "new cgroup '%s' is not usable: %s", path,
                strerror(errno));
        husk_cgroup_remove(path);
        return -1;
    }
    return 0;
}

static int cgroup_procs_contains(const char *path, pid_t child)
{
    char file[PATH_MAX];
    char buf[4096];
    char needle[32];
    const char *p;

    if (snprintf(file, sizeof(file), "%s/cgroup.procs", path) >=
        (int)sizeof(file))
        return 0;
    if (read_text(file, buf, sizeof(buf)) < 0)
        return 0;
    (void)snprintf(needle, sizeof(needle), "%ld", (long)child);
    for (p = buf; *p != '\0'; p++) {
        if (strncmp(p, needle, strlen(needle)) == 0 &&
            (p[strlen(needle)] == '\0' || p[strlen(needle)] == '\n'))
            return 1;
    }
    return 0;
}

static int move_child(const char *path, pid_t child, char *err, size_t errlen)
{
    char procs[PATH_MAX];
    char pid[32];
    char cgroup[PATH_MAX];
    char buf[4096];

    if (snprintf(procs, sizeof(procs), "%s/cgroup.procs", path) >=
        (int)sizeof(procs)) {
        set_err(err, errlen, "cgroup path is too long");
        return -1;
    }
    (void)snprintf(pid, sizeof(pid), "%ld", (long)child);
    if (write_text(procs, pid) < 0) {
        set_err(err, errlen, "move init %ld into cgroup '%s': %s", (long)child,
                path, strerror(errno));
        return -1;
    }
    if (!cgroup_procs_contains(path, child)) {
        set_err(err, errlen, "init %ld is not listed in '%s' after move",
                (long)child, procs);
        return -1;
    }
    if (snprintf(cgroup, sizeof(cgroup), "/proc/%ld/cgroup", (long)child) >=
        (int)sizeof(cgroup)) {
        set_err(err, errlen, "proc path is too long");
        return -1;
    }
    if (read_text(cgroup, buf, sizeof(buf)) < 0) {
        set_err(err, errlen, "read %s: %s", cgroup, strerror(errno));
        return -1;
    }
    {
        const char *slash = strrchr(path, '/');
        const char *base = slash != NULL ? slash + 1 : path;

        if (strstr(buf, base) == NULL) {
            set_err(err, errlen,
                    "init cgroup '%s' does not contain expected component "
                    "'%s'",
                    buf, base);
            return -1;
        }
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

static int recv_bounded(int fd, struct husk_msg *msg, char *err, size_t errlen)
{
    long long deadline = monotonic_ms() + HUSK_MAP_TIMEOUT_MS;

    for (;;) {
        struct pollfd pfd = {.fd = fd, .events = POLLIN};
        long long remaining = deadline - monotonic_ms();
        int r;
        int got;

        if (remaining <= 0) {
            set_err(err, errlen,
                    "timed out after %d ms waiting for cgroup setup request",
                    HUSK_MAP_TIMEOUT_MS);
            return -1;
        }
        r = poll(&pfd, 1, (int)remaining);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            set_err(err, errlen, "poll cgroup handshake: %s", strerror(errno));
            return -1;
        }
        if (r == 0) {
            set_err(err, errlen,
                    "timed out after %d ms waiting for cgroup setup request",
                    HUSK_MAP_TIMEOUT_MS);
            return -1;
        }
        got = husk_recv_msg(fd, msg);
        if (got == 0) {
            set_err(err, errlen, "control socket closed during cgroup setup");
            return -1;
        }
        if (got < 0) {
            set_err(err, errlen, "invalid control message during cgroup setup");
            return -1;
        }
        return 0;
    }
}

int husk_cgroup_parent_handshake(int ctrl_fd, pid_t child, const char *path,
                                 const struct husk_config *cfg, char *err,
                                 size_t errlen)
{
    struct husk_msg msg;

    if (recv_bounded(ctrl_fd, &msg, err, errlen) < 0) {
        kill_and_reap(child);
        return -1;
    }
    if (msg.type != HUSK_MSG_CGROUP_REQUEST) {
        set_err(err, errlen, "unexpected message %u during cgroup setup",
                msg.type);
        kill_and_reap(child);
        return -1;
    }
    /* Limits were written and verified by husk_cgroup_create before the
     * clone. Moving the init does not change them, so do not rewrite them a
     * second time in the hot setup path. */
    (void)cfg;
    if (move_child(path, child, err, errlen) < 0) {
        (void)husk_send_msg(ctrl_fd, HUSK_MSG_CGROUP_ERROR, HUSK_EXIT_SETUP,
                            "%s", err != NULL ? err : "cgroup setup failed");
        kill_and_reap(child);
        return -1;
    }
    if (husk_send_msg(ctrl_fd, HUSK_MSG_CGROUP_READY, 0, "ready") < 0) {
        set_err(err, errlen, "send cgroup acknowledgement: %s",
                strerror(errno));
        kill_and_reap(child);
        return -1;
    }
    return 0;
}

int husk_cgroup_child_wait(int ctrl_fd, char *err, size_t errlen)
{
    struct husk_msg msg;

    if (husk_send_msg(ctrl_fd, HUSK_MSG_CGROUP_REQUEST, 0, "request") < 0) {
        set_err(err, errlen, "send cgroup request: %s", strerror(errno));
        return -1;
    }
    if (recv_bounded(ctrl_fd, &msg, err, errlen) < 0)
        return -1;
    if (msg.type == HUSK_MSG_CGROUP_READY)
        return 0;
    if (msg.type == HUSK_MSG_CGROUP_ERROR) {
        set_err(err, errlen, "%s",
                msg.text[0] != '\0' ? msg.text : "parent rejected cgroup setup");
        return -1;
    }
    set_err(err, errlen, "unexpected message %u during cgroup setup", msg.type);
    return -1;
}

int husk_cgroup_unshare_cgroup_ns(char *err, size_t errlen)
{
    if (unshare(CLONE_NEWCGROUP) < 0) {
        set_err(err, errlen, "unshare(CLONE_NEWCGROUP): %s", strerror(errno));
        return -1;
    }
    return 0;
}

int husk_cgroup_verify_ns(char *err, size_t errlen)
{
    char buf[4096];
    char path[64];

    (void)snprintf(path, sizeof(path), "/proc/self/cgroup");
    if (read_text(path, buf, sizeof(buf)) < 0) {
        set_err(err, errlen, "read /proc/self/cgroup: %s", strerror(errno));
        return -1;
    }
    if (strcmp(buf, "0::/") != 0) {
        set_err(err, errlen,
                "cgroup namespace is not rooted at the container cgroup "
                "(/proc/self/cgroup='%s')",
                buf);
        return -1;
    }
    return 0;
}

void husk_cgroup_remove(const char *path)
{
    int i;

    if (path == NULL || path[0] == '\0')
        return;
    for (i = 0; i < 100; i++) {
        if (rmdir(path) == 0)
            return;
        if (errno == ENOENT)
            return;
        if (errno != EBUSY && errno != ENOTEMPTY)
            break;
        usleep(20000);
    }
    fprintf(stderr, "husk: warning: could not remove cgroup '%s': %s\n", path,
            strerror(errno));
}
