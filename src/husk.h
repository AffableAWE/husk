#ifndef HUSK_H
#define HUSK_H

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>

/* glibc 2.34+ defines this in <unistd.h>; musl and older glibc do not. */
#ifndef CLOSE_RANGE_CLOEXEC
#define CLOSE_RANGE_CLOEXEC (1U << 2)
#endif

#define HUSK_VERSION "0.3.0"

#define HUSK_CTRL_TEXT 512

/* Bounded waits for the rootless user-namespace mapping exchange and for the
 * post-mapping setup handshake. Neither side may wait forever. */
#define HUSK_MAP_TIMEOUT_MS 10000
#define HUSK_SETUP_TIMEOUT_MS 30000

/* Container-side PATH is fixed so command lookup is deterministic and does
 * not depend on the caller's host environment. */
#define HUSK_PATH_DEFAULT \
    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

/* Exit statuses owned by husk itself. A workload may of course exit with any
 * of these values; the stderr message disambiguates. */
#define HUSK_EXIT_USAGE 2    /* bad invocation / bad rootfs path */
#define HUSK_EXIT_SETUP 125  /* namespace, mount, pivot_root, or proc failure */
#define HUSK_EXIT_NOEXEC 126 /* command exists but cannot be executed */
#define HUSK_EXIT_NOTFOUND 127 /* command not found in the rootfs */

enum husk_msg_type {
    HUSK_MSG_READY = 1,
    HUSK_MSG_SETUP_ERROR = 2,
    HUSK_MSG_EXEC_ERROR = 3,
    /* Rootless user-namespace mapping handshake. The child asks the parent to
     * install the single-ID UID/GID maps, and blocks until exactly one of
     * READY or ERROR arrives. */
    HUSK_MSG_MAP_REQUEST = 4,
    HUSK_MSG_MAP_READY = 5,
    HUSK_MSG_MAP_ERROR = 6,
    /* Cgroup setup handshake: the parent creates/configures the unique cgroup,
     * moves the init into it, verifies requested limits, then acknowledges.
     * The child only unshares its cgroup namespace after this acknowledgement. */
    HUSK_MSG_CGROUP_REQUEST = 7,
    HUSK_MSG_CGROUP_READY = 8,
    HUSK_MSG_CGROUP_ERROR = 9,
    HUSK_MSG_NET_REQUEST = 10,
    HUSK_MSG_NET_READY = 11,
    HUSK_MSG_NET_ERROR = 12,
};

struct husk_msg {
    uint32_t type;
    int32_t error;
    char text[HUSK_CTRL_TEXT];
};

struct husk_config {
    const char *rootfs;
    const char *hostname;
    char *const *argv;
    int ctrl_fd;   /* child end of the SOCK_SEQPACKET control socket */
    int parent_fd; /* parent end, closed by the child */
    bool rootless;

    /* Resource controls. cgroup_enabled means an explicit parent was supplied;
     * the *_set flags select controller values. All values are already
     * validated by main(). */
    bool cgroup_enabled;
    const char *cgroup_parent;
    bool memory_set;
    unsigned long long memory_max;
    bool pids_set;
    unsigned long long pids_max;
    bool cpu_set;
    unsigned long long cpu_quota;
    unsigned long long cpu_period;
    bool nofile_set;
    unsigned long long nofile;
    bool fsize_set;
    unsigned long long fsize;

    /* Optional privileged bridge networking. The parent owns lease_fd and the
     * host-side veth; the child closes the lease fd and configures its end. */
    bool bridge_enabled;
    const char *bridge;
    char container_addr_text[64];
    char gateway_text[64];
    int container_prefix;
    unsigned int container_addr; /* network byte order */
    unsigned int gateway_addr;   /* network byte order */
    const char *lease_dir;
    char host_veth[16];
    char peer_veth[16];
    int lease_fd;
    char lease_path[PATH_MAX];
    bool host_veth_created;
};

/* util.c */
int husk_send_msg(int fd, uint32_t type, int error, const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));
/* 1 = message, 0 = clean EOF, -1 = error */
int husk_recv_msg(int fd, struct husk_msg *msg);
void husk_close_fds_from(int lowfd, unsigned int flags);

/* userns.c: rootless mapping handshake over the SOCK_SEQPACKET control
 * socket. The parent installs the maps and acknowledges; the child blocks
 * until the acknowledgement or a bounded failure. Both sides perform their
 * own child cleanup on failure. Return 0 on success, -1 on failure with a
 * human-readable reason in err. */
int husk_userns_parent_map(pid_t child, int ctrl_fd, uid_t host_uid,
                           gid_t host_gid, char *err, size_t errlen);
int husk_userns_child_wait(int ctrl_fd, char *err, size_t errlen);

/* cgroup.c: create/configure a unique cgroup v2 child, move the init into it,
 * verify requested limits before acknowledgement, and remove it afterwards.
 * The parent-side handshake kills and reaps the child on failure. */
int husk_cgroup_create(const char *parent, const struct husk_config *cfg,
                       char *path, size_t pathlen, char *err, size_t errlen);
int husk_cgroup_parent_handshake(int ctrl_fd, pid_t child, const char *path,
                                 const struct husk_config *cfg, char *err,
                                 size_t errlen);
int husk_cgroup_child_wait(int ctrl_fd, char *err, size_t errlen);
int husk_cgroup_unshare_cgroup_ns(char *err, size_t errlen);
int husk_cgroup_verify_ns(char *err, size_t errlen);
void husk_cgroup_remove(const char *path);

/* security.c: rlimits, the documented minimal capability policy,
 * no_new_privs, and the architecture-validated seccomp filter. */
int husk_security_apply_rlimits(const struct husk_config *cfg, char *err,
                                size_t errlen);
int husk_security_prepare_init(char *err, size_t errlen);
int husk_security_workload_drop(char *err, size_t errlen);
int husk_security_init_finalize(char *err, size_t errlen);

/* network.c: isolated networking remains the default. Bridge mode uses
 * rtnetlink to create a veth pair, attach the host end to an existing bridge,
 * move the peer into the container netns, and configure address/loopback/
 * default route in the child. File-backed leases serialize address ownership
 * and recover stale leases. */
int husk_network_validate(struct husk_config *cfg, char *err, size_t errlen);
int husk_network_lease_acquire(struct husk_config *cfg, char *err,
                               size_t errlen);
int husk_network_parent_handshake(int ctrl_fd, pid_t child,
                                  struct husk_config *cfg, char *err,
                                  size_t errlen);
int husk_network_child_wait(int ctrl_fd, char *err, size_t errlen);
int husk_network_configure_child(const struct husk_config *cfg, char *err,
                                 size_t errlen);
void husk_network_cleanup(struct husk_config *cfg);

#ifdef HUSK_TEST_HOOKS
/* Compiled only into the separately built handshake-lifecycle test binary.
 * The normal husk build contains no fault-injection code or test interface. */
void husk_test_mark(const char *name, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
enum {
    HUSK_PERF_CLONE = 0,
    HUSK_PERF_CGROUP = 1,
    HUSK_PERF_NETWORK = 2,
    HUSK_PERF_READY = 3,
    HUSK_PERF_DONE = 4,
};
void husk_perf_mark(int phase);
int husk_test_fail_if(const char *phase);
void husk_test_wait_release(const char *name, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
void husk_test_interruptible_wait(void);
#endif

/* container.c: entry point of the cloned child; runs as PID 1 of the new
 * PID namespace and never returns. */
int husk_child_main(void *arg) __attribute__((noreturn));

#endif
