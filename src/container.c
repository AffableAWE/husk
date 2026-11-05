#define _GNU_SOURCE

#include "husk.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static int g_ctrl_fd = -1;
static volatile sig_atomic_t g_workload_pid = 0;

/* Reported from the workload child through the close-on-exec pipe. kind 0 is
 * an exec errno; kind 1 is a security-policy failure with a text diagnostic. */
struct workload_report {
    int kind;
    int err;
    char text[256];
};

static const int g_forward_signals[] = {
    SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGUSR1, SIGUSR2,
};

static void child_fail(int code, const char *fmt, ...)
    __attribute__((noreturn, format(printf, 2, 3)));

static void child_fail(int code, const char *fmt, ...)
{
    char text[HUSK_CTRL_TEXT];
    va_list ap;

    va_start(ap, fmt);
    (void)vsnprintf(text, sizeof(text), fmt, ap);
    va_end(ap);

#ifdef HUSK_TEST_HOOKS
    husk_test_mark("child-fail", "code=%d text=%s", code, text);
#endif
    husk_send_msg(g_ctrl_fd, HUSK_MSG_SETUP_ERROR, code, "%s", text);
    _exit(code);
}

static void forward_signal(int sig)
{
    pid_t pid = (pid_t)g_workload_pid;
    int saved_errno = errno;

    if (pid > 0)
        (void)kill(pid, sig);
    errno = saved_errno;
}

static void ensure_proc_dir(const char *path, const char *display)
{
    struct stat st;

    if (stat(path, &st) < 0) {
        if (errno != ENOENT)
            child_fail(HUSK_EXIT_SETUP, "stat %s: %s", display,
                       strerror(errno));
        /* A rootfs without /proc is a common minimal-fixture situation. Create
         * the mountpoint rather than refusing; this is the only mutation of
         * the supplied rootfs. */
        if (mkdir(path, 0555) < 0 && errno != EEXIST)
            child_fail(HUSK_EXIT_SETUP, "mkdir %s in rootfs: %s", display,
                       strerror(errno));
    } else if (!S_ISDIR(st.st_mode)) {
        child_fail(HUSK_EXIT_SETUP, "%s in rootfs is not a directory", display);
    }
}

static void mount_proc(const char *path, const char *display)
{
    if (mount("proc", path, "proc", MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL) <
        0)
        child_fail(HUSK_EXIT_SETUP, "mount proc on %s: %s", display,
                   strerror(errno));
}

/* Runs inside the new mount namespace. The host's mount namespace is never
 * touched: clone(CLONE_NEWNS) gave us a private copy, and making the whole
 * tree MS_PRIVATE stops any propagation back to the host. */
static void setup_mounts(const struct husk_config *cfg)
{
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0)
        child_fail(HUSK_EXIT_SETUP, "make / private (MS_PRIVATE): %s",
                   strerror(errno));

    if (mount(cfg->rootfs, cfg->rootfs, NULL, MS_BIND | MS_REC, NULL) < 0)
        child_fail(HUSK_EXIT_SETUP, "bind-mount rootfs '%s': %s",
                   cfg->rootfs, strerror(errno));

    if (chdir(cfg->rootfs) < 0)
        child_fail(HUSK_EXIT_SETUP, "chdir rootfs '%s': %s", cfg->rootfs,
                   strerror(errno));

    /* Rootless adaptation: on an unprivileged user namespace with a
     * bind-mounted root, mounting procfs on "/proc" after pivot_root fails
     * with EPERM. Mount it on the new root's "proc" before pivot_root. The
     * process is already PID 1 of the new PID namespace, so the procfs still
     * describes the container's PID namespace. The privileged path keeps the
     * accepted post-pivot ordering. */
    if (cfg->rootless) {
        ensure_proc_dir("proc", "/proc");
        mount_proc("proc", "/proc");
    }

    /* pivot_root(".", ".") stacks the old root on top of the new root; the
     * following detach unmounts the old root. This is the documented
     * two-call idiom from pivot_root(2) and avoids creating a .oldroot
     * directory inside the supplied rootfs. */
    if (syscall(SYS_pivot_root, ".", ".") < 0)
        child_fail(HUSK_EXIT_SETUP, "pivot_root: %s", strerror(errno));

    if (umount2(".", MNT_DETACH) < 0)
        child_fail(HUSK_EXIT_SETUP, "detach old root: %s", strerror(errno));

    if (chdir("/") < 0)
        child_fail(HUSK_EXIT_SETUP, "chdir / after pivot_root: %s",
                   strerror(errno));

    if (!cfg->rootless) {
        ensure_proc_dir("/proc", "/proc");
        mount_proc("/proc", "/proc");
    }
}

static void reset_workload_signals(void)
{
    sigset_t empty;
    size_t i;

    for (i = 0; i < sizeof(g_forward_signals) / sizeof(g_forward_signals[0]);
         i++)
        (void)signal(g_forward_signals[i], SIG_DFL);
    (void)signal(SIGPIPE, SIG_DFL);
    (void)signal(SIGCHLD, SIG_DFL);

    sigemptyset(&empty);
    (void)sigprocmask(SIG_SETMASK, &empty, NULL);
}

/* The PID-namespace init must have a waitable-child SIGCHLD disposition.
 * SIG_IGN is inherited across execve(2), so it can arrive from a launcher even
 * though this process is a fresh container init. */
static void set_sigchld_default(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_DFL;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGCHLD, &sa, NULL) < 0)
        child_fail(HUSK_EXIT_SETUP, "set SIGCHLD disposition: %s",
                   strerror(errno));
}

enum candidate_status {
    CANDIDATE_MISSING = 0,
    CANDIDATE_NOT_EXECUTABLE = 1,
    CANDIDATE_EXECUTABLE = 2,
};

/* Diagnostic only. The authority is execvp(); this runs after it failed, with
 * the root already switched, so stat() follows absolute symlinks inside the
 * container root, not the host root. */
static int candidate_status(const char *path)
{
    struct stat st;

    if (stat(path, &st) < 0)
        return CANDIDATE_MISSING;
    if (!S_ISREG(st.st_mode))
        return CANDIDATE_NOT_EXECUTABLE;
    if ((st.st_mode & 0111) == 0)
        return CANDIDATE_NOT_EXECUTABLE;
    return CANDIDATE_EXECUTABLE;
}

static void format_exec_error(const char *command, int err, char *text,
                              size_t textlen)
{
    if (strchr(command, '/') != NULL) {
        switch (candidate_status(command)) {
        case CANDIDATE_MISSING:
            snprintf(text, textlen, "command not found in rootfs: %s",
                     command);
            return;
        case CANDIDATE_NOT_EXECUTABLE:
            snprintf(text, textlen,
                     "not executable or not a regular file in rootfs: %s",
                     command);
            return;
        default:
            snprintf(text, textlen,
                     "exec %s: %s (dynamic loader or interpreter missing "
                     "from the rootfs?)",
                     command, strerror(err));
            return;
        }
    }

    {
        const char *p = HUSK_PATH_DEFAULT;
        int found = 0;
        int executable_found = 0;

        while (*p != '\0') {
            const char *end = strchr(p, ':');
            size_t dirlen = end != NULL ? (size_t)(end - p) : strlen(p);
            char candidate[PATH_MAX];
            int n;

            if (dirlen != 0) {
                n = snprintf(candidate, sizeof(candidate), "%.*s/%s",
                             (int)dirlen, p, command);
                if (n > 0 && (size_t)n < sizeof(candidate)) {
                    int st = candidate_status(candidate);

                    if (st != CANDIDATE_MISSING)
                        found = 1;
                    if (st == CANDIDATE_EXECUTABLE)
                        executable_found = 1;
                }
            }
            p = end != NULL ? end + 1 : p + strlen(p);
        }

        if (!found)
            snprintf(text, textlen,
                     "command not found in rootfs (PATH=%s): %s",
                     HUSK_PATH_DEFAULT, command);
        else if (!executable_found)
            snprintf(text, textlen,
                     "not executable in rootfs (PATH=%s): %s",
                     HUSK_PATH_DEFAULT, command);
        else
            snprintf(text, textlen,
                     "exec %s: %s (dynamic loader or interpreter missing "
                     "from the rootfs?)",
                     command, strerror(err));
    }
}

static void run_workload(const struct husk_config *cfg, int exec_pipe)
{
    struct workload_report report;
    int saved_errno;

    memset(&report, 0, sizeof(report));
    reset_workload_signals();

    /* Deterministic container environment. Other host environment variables
     * are inherited (documented limitation). */
    (void)setenv("PATH", HUSK_PATH_DEFAULT, 1);
    (void)setenv("HOME", "/root", 0);
    (void)setenv("HOSTNAME", cfg->hostname, 1);

    /* Mark every descriptor except stdio and the exec-status pipe for
     * close-on-exec. The control socket and pipe already carry CLOEXEC. */
    husk_close_fds_from(3, CLOSE_RANGE_CLOEXEC);

    report.kind = 1;
    report.err = HUSK_EXIT_SETUP;
    if (husk_security_workload_drop(report.text, sizeof(report.text)) < 0) {
        if (write(exec_pipe, &report, sizeof(report)) < 0) { /* best effort */ }
        _exit(HUSK_EXIT_SETUP);
    }

    execvp(cfg->argv[0], cfg->argv);

    saved_errno = errno;
    report.kind = 0;
    report.err = saved_errno;
    (void)snprintf(report.text, sizeof(report.text), "%s", strerror(saved_errno));
    if (write(exec_pipe, &report, sizeof(report)) < 0) { /* best effort */ }
    _exit(saved_errno == ENOENT ? HUSK_EXIT_NOTFOUND : HUSK_EXIT_NOEXEC);
}

/* PID 1 of the new PID namespace. The workload runs as PID 2; PID 1 stays
 * behind to forward signals and reap orphaned children, which the workload
 * itself would not do. */
static void wait_for_workload(pid_t workload)
    __attribute__((noreturn));

static void wait_for_workload(pid_t workload)
{
    int wstatus = 0;
    int have_status = 0;

    for (;;) {
        int st;
        pid_t pid = waitpid(-1, &st, 0);

        if (pid < 0) {
            if (errno == EINTR)
                continue;
            if (errno == ECHILD) {
                fprintf(stderr,
                        "husk: container init: no children left before "
                        "workload was reaped\n");
                _exit(HUSK_EXIT_SETUP);
            }
            fprintf(stderr, "husk: container init: waitpid: %s\n",
                    strerror(errno));
            _exit(HUSK_EXIT_SETUP);
        }

        if (pid == workload) {
            wstatus = st;
            have_status = 1;
            break;
        }
        /* An orphaned grandchild was reparented to us; it has now been
         * reaped. Keep waiting for the workload. */
    }

    if (!have_status)
        _exit(HUSK_EXIT_SETUP);

    /* Do not leave background processes behind once the workload exits. PID 1
     * exiting would make the kernel kill them anyway; doing it explicitly
     * makes ownership and timing clear. */
    (void)kill(-1, SIGKILL);
    while (waitpid(-1, NULL, 0) > 0)
        ;

    if (WIFSIGNALED(wstatus)) {
        int sig = WTERMSIG(wstatus);

        fprintf(stderr, "husk: workload terminated by signal %d (%s)\n", sig,
                strsignal(sig));
        _exit(128 + sig);
    }
    if (WIFEXITED(wstatus))
        _exit(WEXITSTATUS(wstatus));

    _exit(HUSK_EXIT_SETUP);
}

int husk_child_main(void *arg)
{
    struct husk_config *cfg = arg;
    int exec_pipe[2];
    pid_t workload;
    struct workload_report report;
    ssize_t n;
    size_t i;

    close(cfg->parent_fd);
    g_ctrl_fd = cfg->ctrl_fd;

    (void)signal(SIGPIPE, SIG_IGN);

    /* The parent blocked these signals before clone(), so we inherit them
     * blocked. Install handlers before unblocking to avoid a window where a
     * pending signal would take its default action and kill PID 1. */
    {
        struct sigaction sa;

        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = forward_signal;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = SA_RESTART;
        for (i = 0;
             i < sizeof(g_forward_signals) / sizeof(g_forward_signals[0]);
             i++) {
            if (sigaction(g_forward_signals[i], &sa, NULL) < 0)
                child_fail(HUSK_EXIT_SETUP, "sigaction(%d): %s",
                           g_forward_signals[i], strerror(errno));
        }
    }
    set_sigchld_default();

    /* If the parent dies abruptly, take the container down with us instead of
     * leaving an orphaned supervisor and workload running. PID 1 of the new
     * PID namespace cannot see its parent via getppid() (it returns 0), so
     * close the race between clone() and prctl() by checking whether the
     * parent's end of the control socket has gone away. */
    if (prctl(PR_SET_PDEATHSIG, SIGKILL) < 0)
        child_fail(HUSK_EXIT_SETUP, "prctl(PR_SET_PDEATHSIG): %s",
                   strerror(errno));
    if (cfg->lease_fd >= 0)
        (void)close(cfg->lease_fd);
    {
        char peek;
        ssize_t r = recv(cfg->ctrl_fd, &peek, 1, MSG_PEEK | MSG_DONTWAIT);

        if (r == 0)
            child_fail(HUSK_EXIT_SETUP, "parent exited during container setup");
    }

    /* The parent installs the single-ID UID/GID maps and acknowledges. Keep
     * the forwarded signals blocked until the maps exist: the handshake must
     * not be interrupted and no setup may run with unmapped credentials. */
    if (cfg->rootless) {
        char map_err[HUSK_CTRL_TEXT];

        if (husk_userns_child_wait(cfg->ctrl_fd, map_err,
                                   sizeof(map_err)) < 0)
            child_fail(HUSK_EXIT_SETUP, "%s", map_err);

        if (getuid() != 0 || geteuid() != 0 || getgid() != 0 ||
            getegid() != 0)
            child_fail(HUSK_EXIT_SETUP,
                       "user namespace mapping yielded uid=%ld euid=%ld "
                       "gid=%ld egid=%ld instead of 0/0/0/0",
                       (long)getuid(), (long)geteuid(), (long)getgid(),
                       (long)getegid());
    }

    if (cfg->cgroup_enabled) {
        char cg_err[HUSK_CTRL_TEXT];

        if (husk_cgroup_child_wait(cfg->ctrl_fd, cg_err, sizeof(cg_err)) < 0)
            child_fail(HUSK_EXIT_SETUP, "%s", cg_err);
        if (husk_cgroup_unshare_cgroup_ns(cg_err, sizeof(cg_err)) < 0)
            child_fail(HUSK_EXIT_SETUP, "%s", cg_err);
    }

    if (cfg->bridge_enabled) {
        char net_err[HUSK_CTRL_TEXT];

        if (husk_network_child_wait(cfg->ctrl_fd, net_err, sizeof(net_err)) < 0)
            child_fail(HUSK_EXIT_SETUP, "%s", net_err);
        if (husk_network_configure_child(cfg, net_err, sizeof(net_err)) < 0)
            child_fail(HUSK_EXIT_SETUP, "%s", net_err);
    }

    {
        sigset_t empty;

        sigemptyset(&empty);
        (void)sigprocmask(SIG_SETMASK, &empty, NULL);
    }

    if (sethostname(cfg->hostname, strlen(cfg->hostname)) < 0)
        child_fail(HUSK_EXIT_SETUP, "sethostname '%s': %s", cfg->hostname,
                   strerror(errno));

    setup_mounts(cfg);

    if (cfg->cgroup_enabled) {
        char cg_err[HUSK_CTRL_TEXT];

        if (husk_cgroup_verify_ns(cg_err, sizeof(cg_err)) < 0)
            child_fail(HUSK_EXIT_SETUP, "%s", cg_err);
    }

    {
        char sec_err[HUSK_CTRL_TEXT];

        if (husk_security_apply_rlimits(cfg, sec_err, sizeof(sec_err)) < 0)
            child_fail(HUSK_EXIT_SETUP, "%s", sec_err);
        if (husk_security_prepare_init(sec_err, sizeof(sec_err)) < 0)
            child_fail(HUSK_EXIT_SETUP, "%s", sec_err);
    }

#ifdef HUSK_TEST_HOOKS
    if (husk_test_fail_if("child-before-workload-fork"))
        child_fail(HUSK_EXIT_SETUP,
                   "injected failure before workload execution");
    husk_test_wait_release("child-before-workload-fork", "reached");
#endif

    if (pipe2(exec_pipe, O_CLOEXEC) < 0)
        child_fail(HUSK_EXIT_SETUP, "pipe2(exec status): %s", strerror(errno));

    workload = fork();
    if (workload < 0)
        child_fail(HUSK_EXIT_SETUP, "fork workload: %s", strerror(errno));

    if (workload == 0) {
        close(exec_pipe[0]);
        run_workload(cfg, exec_pipe[1]);
        /* not reached */
    }

    g_workload_pid = workload;
    close(exec_pipe[1]);

    /* EOF means execvp() succeeded: the write end was close-on-exec. A full
     * report means exec or workload security setup failed, which lets the
     * parent report the real cause instead of guessing from status 127. */
    memset(&report, 0, sizeof(report));
    do {
        n = read(exec_pipe[0], &report, sizeof(report));
    } while (n < 0 && errno == EINTR);
    close(exec_pipe[0]);

    if (n < 0)
        child_fail(HUSK_EXIT_SETUP, "read exec status: %s", strerror(errno));

    if (n > 0) {
        int st;
        int code;
        char detail[HUSK_CTRL_TEXT];

        while (waitpid(workload, &st, 0) < 0 && errno == EINTR)
            ;
        if ((size_t)n != sizeof(report)) {
            child_fail(HUSK_EXIT_SETUP, "short workload report");
        }
        if (report.kind == 0) {
            code = report.err == ENOENT ? HUSK_EXIT_NOTFOUND
                                        : HUSK_EXIT_NOEXEC;
            format_exec_error(cfg->argv[0], report.err, detail, sizeof(detail));
        } else {
            code = HUSK_EXIT_SETUP;
            (void)snprintf(detail, sizeof(detail), "%s",
                           report.text[0] != '\0' ? report.text
                                                  : "workload security setup "
                                                    "failed");
        }
        husk_send_msg(cfg->ctrl_fd, HUSK_MSG_EXEC_ERROR, code, "%s", detail);
        close(cfg->ctrl_fd);
        _exit(code);
    }

    {
        char sec_err[HUSK_CTRL_TEXT];

        if (husk_security_init_finalize(sec_err, sizeof(sec_err)) < 0)
            child_fail(HUSK_EXIT_SETUP, "%s", sec_err);
    }

    husk_send_msg(cfg->ctrl_fd, HUSK_MSG_READY, 0, "started");
    close(cfg->ctrl_fd);

    wait_for_workload(workload);
}
