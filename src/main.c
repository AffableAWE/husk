#define _GNU_SOURCE

#include "husk.h"

#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 64
#endif

static void print_usage(FILE *out)
{
    fprintf(out,
            "Usage: husk run --rootfs DIR [--hostname NAME] [--rootless] "
            "[--] COMMAND [ARG...]\n"
            "\n"
            "Run COMMAND in a new container built from the supplied rootfs.\n"
            "\n"
            "Options:\n"
            "  --rootfs DIR      Root filesystem directory (required)\n"
            "  --hostname NAME   Container hostname (default: husk)\n"
            "  --rootless        Run as an ordinary user in a new user\n"
            "                    namespace (UID/GID 0 maps to the caller)\n"
            "  --cgroup-parent D Delegated cgroup v2 parent (required for\n"
            "                    cgroup limits; also enables a cgroup ns)\n"
            "  --memory-max B    cgroup memory.max in bytes\n"
            "  --pids-max N      cgroup pids.max\n"
            "  --cpu-max Q P     cgroup cpu.max quota and period in us\n"
            "  --rlimit-nofile N Workload RLIMIT_NOFILE (min 16)\n"
            "  --rlimit-fsize B  Workload RLIMIT_FSIZE in bytes\n"
            "  --bridge BRIDGE   Existing bridge for privileged networking\n"
            "  --container-address CIDR\n"
            "                    Container IPv4 address/prefix for --bridge\n"
            "  --gateway IP      Default gateway for --bridge\n"
            "  --lease-dir DIR   Address-lease directory for --bridge\n"
            "  -h, --help        Show this help and exit\n"
            "  -V, --version     Show version and exit\n"
            "\n"
            "The container gets new mount, PID, UTS, IPC, and network\n"
            "namespaces. Rootless mode also creates a user namespace and maps\n"
            "container UID/GID 0 to the invoking user's single UID/GID.\n"
            "The default network namespace has a down loopback interface,\n"
            "kernel-created inactive tunnel devices, and no external\n"
            "interfaces, addresses, or routes. With --bridge (privileged\n"
            "only), husk creates a veth pair for the named existing bridge.\n"
            "\n"
            "Exit status:\n"
            "  0..125            workload exit status\n"
            "  126               command found but could not be executed\n"
            "  127               command not found (or workload exited 127)\n"
            "  125               container setup failed\n"
            "  2                 invalid invocation or rootfs\n"
            "  128+N             workload or container init killed by signal N\n"
            "\n"
            "--rootless must be invoked by a non-root user and needs\n"
            "unprivileged user namespaces. Without --rootless, husk requires\n"
            "root (CAP_SYS_ADMIN in the initial user namespace).\n"
            "Security policy husk-minimal-v1: the workload has empty capability\n"
            "sets, no_new_privs=1, and an architecture-checked seccomp filter;\n"
            "the init keeps only CAP_KILL after setup. Neither mode is a\n"
            "completed security sandbox for hostile workloads.\n");
}

static void usage_error(const char *fmt, ...)
    __attribute__((noreturn, format(printf, 1, 2)));

static void usage_error(const char *fmt, ...)
{
    va_list ap;

    fputs("husk: ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputs("\nTry 'husk --help' for usage.\n", stderr);
    exit(HUSK_EXIT_USAGE);
}

static void fatal(int code, const char *fmt, ...)
    __attribute__((noreturn, format(printf, 2, 3)));

static void fatal(int code, const char *fmt, ...)
{
    va_list ap;

    fputs("husk: ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(code);
}

static unsigned long long parse_uint(const char *s, unsigned long long min,
                                    unsigned long long max, const char *what)
{
    char *end = NULL;
    unsigned long long v;

    if (s == NULL || s[0] == '\0')
        usage_error("%s requires a decimal integer", what);
    errno = 0;
    v = strtoull(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0' || v < min || v > max)
        usage_error("%s must be a decimal integer in [%llu, %llu]", what, min,
                    max);
    return v;
}

static int status_to_exit(int status)
{
    if (WIFEXITED(status))
        return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) {
        int sig = WTERMSIG(status);

        fprintf(stderr, "husk: container init terminated by signal %d (%s)\n",
                sig, strsignal(sig));
        return 128 + sig;
    }
    fprintf(stderr, "husk: container init ended with an unknown status\n");
    return HUSK_EXIT_SETUP;
}

static void fill_signal_set(sigset_t *set)
{
    sigemptyset(set);
    sigaddset(set, SIGCHLD);
    sigaddset(set, SIGHUP);
    sigaddset(set, SIGINT);
    sigaddset(set, SIGQUIT);
    sigaddset(set, SIGTERM);
    sigaddset(set, SIGUSR1);
    sigaddset(set, SIGUSR2);
}

/* An ignored SIGCHLD disposition is inherited across execve(2). If a launcher
 * did that, children would be auto-reaped and waitpid() would lose their
 * statuses. Establish an explicit waitable-child disposition before clone. */
static void set_sigchld_default(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_DFL;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGCHLD, &sa, NULL) < 0)
        fatal(HUSK_EXIT_SETUP, "set SIGCHLD disposition: %s",
              strerror(errno));
}

static void terminate_and_reap(pid_t child)
{
    (void)kill(child, SIGKILL);
    while (waitpid(child, NULL, 0) < 0 && errno == EINTR)
        continue;
}

static long long monotonic_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0)
        return 0;
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Wait for a child that has already been told to exit. The bound prevents a
 * stuck init from keeping husk in setup forever; it is an absolute monotonic
 * deadline so interrupted waits cannot extend it. */
static int reap_bounded(pid_t child, int timeout_ms, int *status)
{
    long long deadline = monotonic_ms() + timeout_ms;

    for (;;) {
        pid_t r = waitpid(child, status, WNOHANG);
        long long remaining;

        if (r == child)
            return 0;
        if (r < 0 && errno != EINTR)
            return -1;

        remaining = deadline - monotonic_ms();
        if (remaining <= 0)
            return -1;

        {
            struct timespec ts = {.tv_sec = 0, .tv_nsec = 10000000L};

            if (remaining < 10)
                ts.tv_nsec = (long)remaining * 1000000L;
            while (nanosleep(&ts, &ts) < 0 && errno == EINTR)
                continue;
        }
    }
}

/* Wait for the READY/error handshake. Returns 0 when the workload has been
 * exec'd, otherwise the husk-owned exit status to use. The wait is bounded:
 * a setup that never reports and never exits is killed and reaped. */
static int await_start(int ctrl_fd, pid_t child, struct husk_msg *msg)
{
#ifdef HUSK_TEST_HOOKS
    husk_test_interruptible_wait();
#endif
    long long deadline = monotonic_ms() + HUSK_SETUP_TIMEOUT_MS;

    for (;;) {
        struct pollfd pfd = {.fd = ctrl_fd, .events = POLLIN};
        long long remaining = deadline - monotonic_ms();
        int r;
        int got;

        if (remaining <= 0) {
            fprintf(stderr,
                    "husk: timed out after %d ms waiting for container "
                    "setup\n",
                    HUSK_SETUP_TIMEOUT_MS);
            terminate_and_reap(child);
            return HUSK_EXIT_SETUP;
        }
        r = poll(&pfd, 1, (int)remaining);
        if (r < 0) {
            if (errno == EINTR) {
#ifdef HUSK_TEST_HOOKS
                husk_test_mark("parent-setup-eintr", "eintr");
#endif
                continue;
            }
            fprintf(stderr, "husk: poll control socket: %s\n",
                    strerror(errno));
            terminate_and_reap(child);
            return HUSK_EXIT_SETUP;
        }
        if (r == 0) {
            fprintf(stderr,
                    "husk: timed out after %d ms waiting for container "
                    "setup\n",
                    HUSK_SETUP_TIMEOUT_MS);
            terminate_and_reap(child);
            return HUSK_EXIT_SETUP;
        }

        got = husk_recv_msg(ctrl_fd, msg);
        if (got == 0) {
            int status = 0;

            if (reap_bounded(child, 5000, &status) < 0) {
                terminate_and_reap(child);
                status = 0;
            }
            fprintf(stderr,
                    "husk: container init exited during setup without "
                    "reporting an error (status %d)\n",
                    WIFEXITED(status) ? WEXITSTATUS(status) : status);
            return HUSK_EXIT_SETUP;
        }
        if (got < 0) {
            fprintf(stderr, "husk: read control socket: %s\n",
                    strerror(errno));
            terminate_and_reap(child);
            return HUSK_EXIT_SETUP;
        }

        if (msg->type == HUSK_MSG_READY)
            return 0;
        if (msg->type == HUSK_MSG_SETUP_ERROR ||
            msg->type == HUSK_MSG_EXEC_ERROR) {
            int status = 0;

            if (reap_bounded(child, 5000, &status) < 0)
                terminate_and_reap(child);
            fprintf(stderr, "husk: %s\n", msg->text);
            return msg->error != 0 ? msg->error : HUSK_EXIT_SETUP;
        }

        fprintf(stderr, "husk: unknown control message type %u\n", msg->type);
        terminate_and_reap(child);
        return HUSK_EXIT_SETUP;
    }
}

/* Forward the signals a terminal or supervisor may send, then reap the
 * container init and map its status to husk's exit status. */
static int supervise(pid_t child, int sig_fd, sigset_t *mask)
{
    for (;;) {
        struct pollfd pfd = {.fd = sig_fd, .events = POLLIN};
        pid_t r;
        int status;
        int pr;

        r = waitpid(child, &status, WNOHANG);
        if (r == child)
            return status_to_exit(status);
        if (r < 0 && errno != EINTR)
            fatal(HUSK_EXIT_SETUP, "waitpid: %s", strerror(errno));

        pr = ppoll(&pfd, 1, NULL, mask);
        if (pr < 0) {
            if (errno == EINTR)
                continue;
            fatal(HUSK_EXIT_SETUP, "ppoll: %s", strerror(errno));
        }
        if (pr == 0)
            continue;

        if (pfd.revents & POLLIN) {
            struct signalfd_siginfo si;

            while (read(sig_fd, &si, sizeof(si)) == (ssize_t)sizeof(si)) {
                int sig = (int)si.ssi_signo;

                if (sig == SIGCHLD)
                    continue;
                if (sig == SIGHUP || sig == SIGINT || sig == SIGQUIT ||
                    sig == SIGTERM || sig == SIGUSR1 || sig == SIGUSR2) {
                    if (kill(child, sig) < 0 && errno != ESRCH)
                        fprintf(stderr,
                                "husk: forward signal %d: %s\n", sig,
                                strerror(errno));
                }
            }
        }
    }
}

int main(int argc, char **argv)
{
    const char *rootfs_arg = NULL;
    const char *hostname = "husk";
    const char *cgroup_parent_arg = NULL;
    const char *bridge_arg = NULL;
    const char *container_addr_arg = NULL;
    const char *gateway_arg = NULL;
    const char *lease_dir_arg = NULL;
    char rootfs[PATH_MAX];
    char cgroup_parent[PATH_MAX];
    char cgroup_path[PATH_MAX];
    char map_err[HUSK_CTRL_TEXT];
    char cgroup_err[HUSK_CTRL_TEXT];
    struct husk_config cfg;
    struct husk_msg msg;
    struct stat st;
    sigset_t mask;
    void *child_stack;
    size_t stack_size;
    uid_t host_uid;
    gid_t host_gid;
    bool rootless = false;
    bool cgroup_enabled = false;
    bool cgroup_created = false;
    bool bridge_enabled = false;
    bool memory_set = false;
    bool pids_set = false;
    bool cpu_set = false;
    bool nofile_set = false;
    bool fsize_set = false;
    unsigned long long memory_max = 0;
    unsigned long long pids_max = 0;
    unsigned long long cpu_quota = 0;
    unsigned long long cpu_period = 0;
    unsigned long long nofile = 0;
    unsigned long long fsize = 0;
    int clone_flags;
    pid_t child;
    int sig_fd;
    int sv[2];
    int i;
    int rc;

    if (argc < 2)
        usage_error("missing command");
    if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        print_usage(stdout);
        return 0;
    }
    if (strcmp(argv[1], "-V") == 0 || strcmp(argv[1], "--version") == 0) {
        printf("husk %s\n", HUSK_VERSION);
        return 0;
    }
    if (strcmp(argv[1], "run") != 0)
        usage_error("unknown command '%s'", argv[1]);

    i = 2;
    while (i < argc) {
        const char *a = argv[i];

        if (strcmp(a, "--") == 0) {
            i++;
            break;
        }
        if (strcmp(a, "--rootfs") == 0) {
            if (i + 1 >= argc)
                usage_error("--rootfs requires a directory argument");
            rootfs_arg = argv[++i];
            i++;
            continue;
        }
        if (strncmp(a, "--rootfs=", 9) == 0) {
            rootfs_arg = a + 9;
            i++;
            continue;
        }
        if (strcmp(a, "--hostname") == 0) {
            if (i + 1 >= argc)
                usage_error("--hostname requires an argument");
            hostname = argv[++i];
            i++;
            continue;
        }
        if (strncmp(a, "--hostname=", 11) == 0) {
            hostname = a + 11;
            i++;
            continue;
        }
        if (strcmp(a, "--rootless") == 0) {
            rootless = true;
            i++;
            continue;
        }
        if (strcmp(a, "--cgroup-parent") == 0) {
            if (i + 1 >= argc)
                usage_error("--cgroup-parent requires a directory argument");
            cgroup_parent_arg = argv[++i];
            i++;
            continue;
        }
        if (strncmp(a, "--cgroup-parent=", 16) == 0) {
            cgroup_parent_arg = a + 16;
            i++;
            continue;
        }
        if (strcmp(a, "--bridge") == 0) {
            if (i + 1 >= argc)
                usage_error("--bridge requires an interface name");
            bridge_arg = argv[++i];
            bridge_enabled = true;
            i++;
            continue;
        }
        if (strncmp(a, "--bridge=", 9) == 0) {
            bridge_arg = a + 9;
            bridge_enabled = true;
            i++;
            continue;
        }
        if (strcmp(a, "--container-address") == 0) {
            if (i + 1 >= argc)
                usage_error("--container-address requires IPv4/PREFIX");
            container_addr_arg = argv[++i];
            i++;
            continue;
        }
        if (strncmp(a, "--container-address=", 20) == 0) {
            container_addr_arg = a + 20;
            i++;
            continue;
        }
        if (strcmp(a, "--gateway") == 0) {
            if (i + 1 >= argc)
                usage_error("--gateway requires an IPv4 address");
            gateway_arg = argv[++i];
            i++;
            continue;
        }
        if (strncmp(a, "--gateway=", 10) == 0) {
            gateway_arg = a + 10;
            i++;
            continue;
        }
        if (strcmp(a, "--lease-dir") == 0) {
            if (i + 1 >= argc)
                usage_error("--lease-dir requires a directory");
            lease_dir_arg = argv[++i];
            i++;
            continue;
        }
        if (strncmp(a, "--lease-dir=", 12) == 0) {
            lease_dir_arg = a + 12;
            i++;
            continue;
        }
        if (strcmp(a, "--memory-max") == 0) {
            if (i + 1 >= argc)
                usage_error("--memory-max requires a byte count");
            memory_max = parse_uint(argv[++i], 1, 1ULL << 50, "--memory-max");
            memory_set = true;
            i++;
            continue;
        }
        if (strncmp(a, "--memory-max=", 13) == 0) {
            memory_max = parse_uint(a + 13, 1, 1ULL << 50, "--memory-max");
            memory_set = true;
            i++;
            continue;
        }
        if (strcmp(a, "--pids-max") == 0) {
            if (i + 1 >= argc)
                usage_error("--pids-max requires a count");
            pids_max = parse_uint(argv[++i], 1, 1000000, "--pids-max");
            pids_set = true;
            i++;
            continue;
        }
        if (strncmp(a, "--pids-max=", 11) == 0) {
            pids_max = parse_uint(a + 11, 1, 1000000, "--pids-max");
            pids_set = true;
            i++;
            continue;
        }
        if (strcmp(a, "--cpu-max") == 0) {
            if (i + 2 >= argc)
                usage_error("--cpu-max requires QUOTA and PERIOD");
            cpu_quota = parse_uint(argv[++i], 1, 1000000000, "--cpu-max quota");
            cpu_period =
                parse_uint(argv[++i], 1000, 1000000, "--cpu-max period");
            cpu_set = true;
            i++;
            continue;
        }
        if (strcmp(a, "--rlimit-nofile") == 0) {
            if (i + 1 >= argc)
                usage_error("--rlimit-nofile requires a count");
            nofile = parse_uint(argv[++i], 16, 1048576, "--rlimit-nofile");
            nofile_set = true;
            i++;
            continue;
        }
        if (strncmp(a, "--rlimit-nofile=", 16) == 0) {
            nofile = parse_uint(a + 16, 16, 1048576, "--rlimit-nofile");
            nofile_set = true;
            i++;
            continue;
        }
        if (strcmp(a, "--rlimit-fsize") == 0) {
            if (i + 1 >= argc)
                usage_error("--rlimit-fsize requires a byte count");
            fsize = parse_uint(argv[++i], 0, 1ULL << 50, "--rlimit-fsize");
            fsize_set = true;
            i++;
            continue;
        }
        if (strncmp(a, "--rlimit-fsize=", 15) == 0) {
            fsize = parse_uint(a + 15, 0, 1ULL << 50, "--rlimit-fsize");
            fsize_set = true;
            i++;
            continue;
        }
        if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
            print_usage(stdout);
            return 0;
        }
        if (a[0] == '-' && a[1] != '\0')
            usage_error("unknown option '%s'", a);
        break;
    }

    if (rootfs_arg == NULL)
        usage_error("--rootfs is required");
    if (rootfs_arg[0] == '\0')
        usage_error("--rootfs must not be empty");
    if (i >= argc)
        usage_error("missing command (use '-- COMMAND [ARG...]')");
    if (argv[i][0] == '\0')
        usage_error("command must not be empty");

    if (hostname[0] == '\0')
        usage_error("--hostname must not be empty");
    if (strlen(hostname) > (size_t)HOST_NAME_MAX)
        usage_error("--hostname is longer than %d bytes", HOST_NAME_MAX);
    {
        const unsigned char *c = (const unsigned char *)hostname;

        for (; *c != '\0'; c++) {
            if (*c <= 0x20 || *c == '/' || *c == 0x7f)
                usage_error("--hostname contains an invalid character");
        }
    }

    if ((memory_set || pids_set || cpu_set) && cgroup_parent_arg == NULL)
        usage_error("cgroup limits require an explicit --cgroup-parent");
    if (cgroup_parent_arg != NULL) {
        char check[PATH_MAX];

        if (cgroup_parent_arg[0] == '\0')
            usage_error("--cgroup-parent must not be empty");
        if (realpath(cgroup_parent_arg, cgroup_parent) == NULL)
            fatal(HUSK_EXIT_USAGE, "invalid cgroup parent '%s': %s",
                  cgroup_parent_arg, strerror(errno));
        if (stat(cgroup_parent, &st) < 0 || !S_ISDIR(st.st_mode))
            fatal(HUSK_EXIT_USAGE, "invalid cgroup parent '%s': not a directory",
                  cgroup_parent);
        if (snprintf(check, sizeof(check), "%s/cgroup.controllers",
                     cgroup_parent) >= (int)sizeof(check) ||
            access(check, F_OK) < 0)
            fatal(HUSK_EXIT_USAGE,
                  "invalid cgroup parent '%s': not a cgroup v2 directory",
                  cgroup_parent);
        cgroup_enabled = true;
    }

    if (bridge_enabled) {
        if (!container_addr_arg || !gateway_arg || !lease_dir_arg)
            usage_error("--bridge requires --container-address, --gateway, "
                        "and --lease-dir");
        if (rootless)
            fatal(HUSK_EXIT_SETUP,
                  "bridge networking requires privileged mode with host "
                  "CAP_NET_ADMIN; rootless mode supports isolated networking "
                  "only");
        if (strlen(container_addr_arg) >= sizeof(cfg.container_addr_text) ||
            strlen(gateway_arg) >= sizeof(cfg.gateway_text))
            usage_error("network address is too long");
        strcpy(cfg.container_addr_text, container_addr_arg);
        strcpy(cfg.gateway_text, gateway_arg);
    } else if (container_addr_arg || gateway_arg || lease_dir_arg) {
        usage_error("--container-address/--gateway/--lease-dir require "
                    "--bridge");
    }

    if (realpath(rootfs_arg, rootfs) == NULL)
        fatal(HUSK_EXIT_USAGE, "invalid rootfs '%s': %s", rootfs_arg,
              strerror(errno));
    if (stat(rootfs, &st) < 0)
        fatal(HUSK_EXIT_USAGE, "invalid rootfs '%s': %s", rootfs,
              strerror(errno));
    if (!S_ISDIR(st.st_mode))
        fatal(HUSK_EXIT_USAGE, "invalid rootfs '%s': not a directory", rootfs);
    if (strcmp(rootfs, "/") == 0)
        fatal(HUSK_EXIT_USAGE,
              "invalid rootfs '/': refusing to pivot_root on the host root");

    host_uid = geteuid();
    host_gid = getegid();

    if (rootless) {
        if (host_uid == 0)
            fatal(HUSK_EXIT_USAGE,
                  "--rootless must be run as a non-root user; omit --rootless "
                  "for the privileged mode");
    } else if (host_uid != 0) {
        fatal(HUSK_EXIT_SETUP,
              "requires root with CAP_SYS_ADMIN in the initial user namespace; "
              "run with --rootless as an ordinary user for the user-namespace "
              "mode");
    }

    /* Command resolution is deliberately NOT done here. Host-side stat()
     * follows absolute symlinks against the host root and cannot reproduce
     * the container's PATH search semantics. Resolution happens in the
     * workload after pivot_root, and exec failures are reported through the
     * control handshake with the documented 126/127 statuses. */

    set_sigchld_default();

    /* Do not leak unrelated descriptors inherited from the caller. */
    husk_close_fds_from(3, 0);

    fill_signal_set(&mask);
    if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0)
        fatal(HUSK_EXIT_SETUP, "block signals: %s", strerror(errno));

    /* The parent writes /proc/<child>/uid_map and gid_map. If a credential
     * transition cleared dumpability, the proc files can be owned by root and
     * the ordinary-user parent cannot write them. Make the parent dumpable
     * before creating the namespace. */
    if (rootless && prctl(PR_SET_DUMPABLE, 1) < 0)
        fatal(HUSK_EXIT_SETUP, "prctl(PR_SET_DUMPABLE): %s", strerror(errno));

    sig_fd = signalfd(-1, &mask, SFD_CLOEXEC | SFD_NONBLOCK);
    if (sig_fd < 0)
        fatal(HUSK_EXIT_SETUP, "signalfd: %s", strerror(errno));

    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sv) < 0)
        fatal(HUSK_EXIT_SETUP, "socketpair(SOCK_SEQPACKET): %s",
              strerror(errno));

    stack_size = 1024 * 1024;
    child_stack = mmap(NULL, stack_size, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
    if (child_stack == MAP_FAILED)
        fatal(HUSK_EXIT_SETUP, "mmap child stack: %s", strerror(errno));

    memset(&cfg, 0, sizeof(cfg));
    cfg.rootfs = rootfs;
    cfg.hostname = hostname;
    cfg.argv = &argv[i];
    cfg.ctrl_fd = sv[1];
    cfg.parent_fd = sv[0];
    cfg.rootless = rootless;
    cfg.cgroup_enabled = cgroup_enabled;
    cfg.cgroup_parent = cgroup_enabled ? cgroup_parent : NULL;
    cfg.memory_set = memory_set;
    cfg.memory_max = memory_max;
    cfg.pids_set = pids_set;
    cfg.pids_max = pids_max;
    cfg.cpu_set = cpu_set;
    cfg.cpu_quota = cpu_quota;
    cfg.cpu_period = cpu_period;
    cfg.nofile_set = nofile_set;
    cfg.nofile = nofile;
    cfg.fsize_set = fsize_set;
    cfg.fsize = fsize;
    cfg.bridge_enabled = bridge_enabled;
    cfg.bridge = bridge_arg;
    cfg.lease_dir = lease_dir_arg;
    cfg.lease_fd = -1;
    cfg.lease_path[0] = '\0';
    cfg.host_veth_created = false;
    if (bridge_enabled) {
        (void)snprintf(cfg.container_addr_text, sizeof(cfg.container_addr_text),
                       "%s", container_addr_arg);
        (void)snprintf(cfg.gateway_text, sizeof(cfg.gateway_text), "%s",
                       gateway_arg);
    }

    if (cgroup_enabled) {
        if (husk_cgroup_create(cgroup_parent, &cfg, cgroup_path,
                               sizeof(cgroup_path), cgroup_err,
                               sizeof(cgroup_err)) < 0) {
            husk_network_cleanup(&cfg);
            fatal(HUSK_EXIT_SETUP, "cgroup setup failed: %s", cgroup_err);
        }
        cgroup_created = true;
    }

#ifdef HUSK_TEST_HOOKS
    if (husk_test_fail_if("after-cgroup-acquire")) {
        if (cgroup_created)
            husk_cgroup_remove(cgroup_path);
        fatal(HUSK_EXIT_SETUP, "injected failure after cgroup acquisition");
    }
#endif

    if (bridge_enabled) {
        char net_err[HUSK_CTRL_TEXT];

        (void)snprintf(cfg.host_veth, sizeof(cfg.host_veth), "hv%08x",
                       (unsigned int)getpid());
        (void)snprintf(cfg.peer_veth, sizeof(cfg.peer_veth), "cv%08x",
                       (unsigned int)getpid());
        if (husk_network_validate(&cfg, net_err, sizeof(net_err)) < 0) {
            if (cgroup_created)
                husk_cgroup_remove(cgroup_path);
            fatal(HUSK_EXIT_SETUP, "network setup failed: %s", net_err);
        }
        if (husk_network_lease_acquire(&cfg, net_err, sizeof(net_err)) < 0) {
            if (cgroup_created)
                husk_cgroup_remove(cgroup_path);
            fatal(HUSK_EXIT_SETUP, "network setup failed: %s", net_err);
        }
    }

#ifdef HUSK_TEST_HOOKS
    if (husk_test_fail_if("after-lease-acquire")) {
        if (bridge_enabled)
            husk_network_cleanup(&cfg);
        if (cgroup_created)
            husk_cgroup_remove(cgroup_path);
        fatal(HUSK_EXIT_SETUP, "injected failure after lease acquisition");
    }
#endif

    clone_flags = CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWIPC |
                  CLONE_NEWNET | SIGCHLD;
    if (rootless)
        clone_flags |= CLONE_NEWUSER;

    child = clone(husk_child_main, (char *)child_stack + stack_size,
                  clone_flags, &cfg);
    if (child < 0) {
        int saved = errno;

        close(sv[0]);
        close(sv[1]);
        close(sig_fd);
        munmap(child_stack, stack_size);
        if (cgroup_created)
            husk_cgroup_remove(cgroup_path);
        if (bridge_enabled)
            husk_network_cleanup(&cfg);
        if (rootless)
            fatal(HUSK_EXIT_SETUP,
                  "clone new rootless namespaces: %s (unprivileged user "
                  "namespaces may be disabled or restricted by the kernel or "
                  "the container runtime)",
                  strerror(saved));
        fatal(HUSK_EXIT_SETUP,
              "clone new namespaces: %s (this MVP needs a privileged Linux "
              "environment with CAP_SYS_ADMIN)",
              strerror(saved));
    }

    close(sv[1]);
    munmap(child_stack, stack_size);
#ifdef HUSK_TEST_HOOKS
    husk_perf_mark(HUSK_PERF_CLONE);
#endif

    if (rootless) {
        if (husk_userns_parent_map(child, sv[0], host_uid, host_gid, map_err,
                                   sizeof(map_err)) < 0) {
            close(sv[0]);
            close(sig_fd);
            if (cgroup_created)
                husk_cgroup_remove(cgroup_path);
            if (bridge_enabled)
                husk_network_cleanup(&cfg);
            fprintf(stderr, "husk: rootless user-namespace mapping failed: "
                            "%s\n",
                    map_err);
            return HUSK_EXIT_SETUP;
        }
    }

    if (cgroup_enabled) {
        if (husk_cgroup_parent_handshake(sv[0], child, cgroup_path, &cfg,
                                         cgroup_err,
                                         sizeof(cgroup_err)) < 0) {
            close(sv[0]);
            close(sig_fd);
            husk_cgroup_remove(cgroup_path);
            if (bridge_enabled)
                husk_network_cleanup(&cfg);
            fprintf(stderr, "husk: cgroup setup failed: %s\n", cgroup_err);
            return HUSK_EXIT_SETUP;
        }
    }

#ifdef HUSK_TEST_HOOKS
    husk_perf_mark(HUSK_PERF_CGROUP);
#endif

    if (bridge_enabled) {
        char net_err[HUSK_CTRL_TEXT];

        if (husk_network_parent_handshake(sv[0], child, &cfg, net_err,
                                          sizeof(net_err)) < 0) {
            close(sv[0]);
            close(sig_fd);
            husk_cgroup_remove(cgroup_path);
            husk_network_cleanup(&cfg);
            fprintf(stderr, "husk: network setup failed: %s\n", net_err);
            return HUSK_EXIT_SETUP;
        }
    }

#ifdef HUSK_TEST_HOOKS
    husk_perf_mark(HUSK_PERF_NETWORK);
#endif

    rc = await_start(sv[0], child, &msg);
    close(sv[0]);
    if (rc != 0) {
        close(sig_fd);
        if (cgroup_created)
            husk_cgroup_remove(cgroup_path);
        if (bridge_enabled)
            husk_network_cleanup(&cfg);
        return rc;
    }

#ifdef HUSK_TEST_HOOKS
    husk_perf_mark(HUSK_PERF_READY);
#endif

    rc = supervise(child, sig_fd, &mask);
    close(sig_fd);
    if (cgroup_created)
        husk_cgroup_remove(cgroup_path);
    if (bridge_enabled)
        husk_network_cleanup(&cfg);
#ifdef HUSK_TEST_HOOKS
    husk_perf_mark(HUSK_PERF_DONE);
#endif
    return rc;
}
