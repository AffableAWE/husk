/* Test helper: run a command in a dedicated session/process group, record
 * ownership, and hold the group open until the harness releases it.
 *
 * Usage: owned_run RECORD -- COMMAND [ARG...]
 *
 * RECORD receives: "<owner-pid> <owner-starttime> <pgid> <child-pid>".
 * After the child exits, the helper writes "<exit-code> <leftover-count>
 * [<pid>...]" to RECORD.status and waits (bounded) for RECORD.release. Only
 * then does it kill and reap processes that are in its own live process group.
 * The helper is the group leader, so the PGID cannot be recycled while this
 * process is alive; the harness can therefore treat the recorded PGID as owned
 * exactly as long as the owner identity still matches.
 *
 * The supervisor itself is never reported as a leftover.
 */
#define _GNU_SOURCE

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define GROUP_MAX 4096
#define RELEASE_WAIT_MS 10000
#define SETTLE_MS 250
#define POLL_MS 50

static volatile sig_atomic_t g_stop;

static void handle_stop(int sig)
{
    g_stop = sig;
}

static int read_proc_pgrp(pid_t pid, pid_t *pgrp)
{
    char path[64];
    char buf[4096];
    char *after;
    int ppid;
    int fd;
    ssize_t n;

    snprintf(path, sizeof(path), "/proc/%ld/stat", (long)pid);
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0)
        return -1;
    buf[n] = '\0';

    after = strrchr(buf, ')');
    if (after == NULL)
        return -1;
    if (sscanf(after + 1, " %*c %d %d", &ppid, pgrp) != 2)
        return -1;
    (void)ppid;
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
    if (tok == NULL)
        return 0;
    return strtoull(tok, NULL, 10);
}

static int write_record(const char *path, pid_t child, unsigned long long start)
{
    char buf[256];
    int fd;
    int n;
    ssize_t written;

    n = snprintf(buf, sizeof(buf), "%ld %llu %ld %ld\n", (long)getpid(),
                 start, (long)getpgrp(), (long)child);
    if (n < 0 || (size_t)n >= sizeof(buf))
        return -1;

    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0)
        return -1;
    written = write(fd, buf, (size_t)n);
    close(fd);
    return written == (ssize_t)n ? 0 : -1;
}

/* Collect processes whose kernel process-group is the group this helper
 * created, excluding the helper itself. The helper is the live group leader,
 * so this is explicit ownership rather than a name/command-line match. */
static size_t group_others(pid_t pgid, pid_t *out, size_t max)
{
    DIR *dir = opendir("/proc");
    struct dirent *de;
    size_t n = 0;

    if (dir == NULL)
        return 0;
    while ((de = readdir(dir)) != NULL) {
        pid_t pid;
        pid_t pgrp;

        if (!isdigit((unsigned char)de->d_name[0]))
            continue;
        pid = (pid_t)strtol(de->d_name, NULL, 10);
        if (pid == getpid())
            continue;
        if (read_proc_pgrp(pid, &pgrp) == 0 && pgrp == pgid) {
            if (n < max)
                out[n] = pid;
            n++;
        }
    }
    closedir(dir);
    return n;
}

static void kill_group_others(pid_t pgid)
{
    pid_t pids[GROUP_MAX];
    size_t n;
    size_t i;

    n = group_others(pgid, pids, GROUP_MAX);
    for (i = 0; i < n && i < GROUP_MAX; i++)
        (void)kill(pids[i], SIGKILL);
}

static void reap_all(void)
{
    for (;;) {
        pid_t pid = waitpid(-1, NULL, 0);

        if (pid > 0)
            continue;
        if (pid < 0 && errno == EINTR)
            continue;
        break;
    }
}

/* Reap children that have already exited, without blocking and without
 * signalling anything. Zombies are not running workload leftovers. */
static void reap_available(void)
{
    while (waitpid(-1, NULL, WNOHANG) > 0)
        continue;
}

static int write_status(const char *record, int rc, pid_t pgid)
{
    char final[4096];
    char tmp[4096];
    pid_t pids[GROUP_MAX];
    size_t n;
    size_t i;
    FILE *f;

    if (snprintf(final, sizeof(final), "%s.status", record) >=
        (int)sizeof(final))
        return -1;
    if (snprintf(tmp, sizeof(tmp), "%s.status.tmp", record) >=
        (int)sizeof(tmp))
        return -1;

    n = group_others(pgid, pids, GROUP_MAX);
    f = fopen(tmp, "w");
    if (f == NULL)
        return -1;
    fprintf(f, "%d %zu", rc, n);
    for (i = 0; i < n && i < GROUP_MAX; i++)
        fprintf(f, " %ld", (long)pids[i]);
    fputc('\n', f);
    if (fclose(f) != 0)
        return -1;
    return rename(tmp, final);
}

/* Wait for the harness acknowledgement, bounded so a vanished harness cannot
 * leave the supervisor alive forever. */
static int wait_for_release(const char *path)
{
    struct timespec req;
    int waited;

    for (waited = 0; waited < RELEASE_WAIT_MS; waited += POLL_MS) {
        if (access(path, F_OK) == 0)
            return 0;
        req.tv_sec = 0;
        req.tv_nsec = (long)POLL_MS * 1000000L;
        while (nanosleep(&req, &req) < 0 && errno == EINTR)
            continue;
    }
    return access(path, F_OK) == 0 ? 0 : -1;
}

/* Give the runtime's own asynchronous teardown a brief grace period before
 * taking the observation snapshot. This is not cleanup: nothing is signalled
 * and the owned group is untouched. */
static void settle_before_observation(void)
{
    struct timespec req;

    req.tv_sec = 0;
    req.tv_nsec = (long)SETTLE_MS * 1000000L;
    while (nanosleep(&req, &req) < 0 && errno == EINTR)
        continue;
}

static int status_to_rc(int status)
{
    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    if (WIFSIGNALED(status))
        return 128 + WTERMSIG(status);
    return 125;
}

int main(int argc, char **argv)
{
    const char *record;
    const char *command;
    char release[4096];
    struct sigaction sa;
    struct sigaction dfl;
    unsigned long long start;
    pid_t child;
    pid_t pgid;
    int status = 0;
    int child_done = 0;
    int forwarded = 0;
    int rc;
    int sigs[] = {SIGTERM, SIGINT, SIGHUP, SIGQUIT};
    size_t i;

    if (argc < 4 || strcmp(argv[2], "--") != 0) {
        fprintf(stderr, "usage: %s RECORD -- COMMAND [ARG...]\n", argv[0]);
        return 2;
    }
    record = argv[1];
    command = argv[3];
    if (snprintf(release, sizeof(release), "%s.release", record) >=
        (int)sizeof(release)) {
        fprintf(stderr, "owned_run: record path too long\n");
        return 2;
    }

    if (setsid() < 0) {
        perror("owned_run: setsid");
        return 111;
    }
    if (prctl(PR_SET_CHILD_SUBREAPER, 1) < 0) {
        perror("owned_run: prctl(PR_SET_CHILD_SUBREAPER)");
        return 111;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_stop;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    for (i = 0; i < sizeof(sigs) / sizeof(sigs[0]); i++) {
        if (sigaction(sigs[i], &sa, NULL) < 0) {
            perror("owned_run: sigaction");
            return 111;
        }
    }

    start = self_starttime();
    child = fork();
    if (child < 0) {
        perror("owned_run: fork");
        return 111;
    }
    if (child == 0) {
        memset(&dfl, 0, sizeof(dfl));
        dfl.sa_handler = SIG_DFL;
        sigemptyset(&dfl.sa_mask);
        for (i = 0; i < sizeof(sigs) / sizeof(sigs[0]); i++)
            (void)sigaction(sigs[i], &dfl, NULL);
        (void)signal(SIGPIPE, SIG_DFL);
        execvp(command, &argv[3]);
        perror("owned_run: execvp");
        _exit(127);
    }

    pgid = getpgrp();
    if (write_record(record, child, start) < 0) {
        perror("owned_run: write record");
        (void)kill(child, SIGKILL);
        (void)waitpid(child, NULL, 0);
        return 111;
    }

    while (!child_done) {
        pid_t pid;

        if (g_stop != 0 && !forwarded) {
            (void)kill(child, (int)g_stop);
            forwarded = 1;
        }

        pid = waitpid(-1, &status, 0);
        if (pid > 0) {
            if (pid == child)
                child_done = 1;
            continue;
        }
        if (pid < 0 && errno == EINTR)
            continue;
        if (pid < 0 && errno == ECHILD)
            break;
        perror("owned_run: waitpid");
        break;
    }

    rc = child_done ? status_to_rc(status) : 125;
    settle_before_observation();
    reap_available();
    if (write_status(record, rc, pgid) < 0)
        fprintf(stderr, "owned_run: cannot write status for %s\n", record);

    /* Keep ownership alive while the harness observes RECORD.status. */
    (void)wait_for_release(release);

    kill_group_others(pgid);
    reap_all();
    return rc;
}
